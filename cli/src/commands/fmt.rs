use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{fs, io, process};

use anyhow::Context;
use clap::{arg, value_parser, ArgAction, ArgMatches, Command};
use crossterm::tty::IsTty;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Green, Red, Yellow};
use yansi::Paint;
use yara_x_fmt::{Formatter, Indentation};

use crate::config::Config;
use crate::walk::Message;
use crate::{help, walk};

pub fn fmt() -> Command {
    super::command("fmt")
        .about("Format YARA source files")
        // Keep options sorted alphabetically by their long name.
        .arg(
            arg!(<PATH>)
                .help("Path to YARA source file or directory")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-c --check  "Run in 'check' mode")
                .long_help(help::FMT_CHECK_MODE),
        )
        .arg(
            arg!(-f --filter <PATTERN>)
                .help("Check files that match the given pattern only")
                .long_help(help::FMT_FILTER_LONG_HELP)
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-p --"threads" <NUM_THREADS>)
                .help("Use the given number of threads")
                .long_help(help::THREADS_LONG_HELP)
                .required(false)
                .value_parser(value_parser!(u8).range(1..)),
        )
        .arg(
            arg!(-r - -"recursive"[MAX_DEPTH])
                .help("Walk directories recursively up to a given depth")
                .long_help(help::RECURSIVE_LONG_HELP)
                .default_missing_value("1000")
                .require_equals(true)
                .value_parser(value_parser!(usize)),
        )
        .arg(
            arg!(-t - -"tab-size" <NUM_SPACES>)
                .help("Tab size (in spaces) used in source files")
                .long_help(help::FMT_TAB_SIZE)
                .default_value("4")
                .value_parser(value_parser!(usize)),
        )
}

pub fn exec_fmt(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let path = args.get_one::<PathBuf>("PATH").unwrap();
    let check = args.get_flag("check");
    let tab_size = args.get_one::<usize>("tab-size").unwrap();
    let recursive = args.get_one::<usize>("recursive");
    let filters = args.get_many::<String>("filter");
    let num_threads = args.get_one::<u8>("threads");

    let formatter = Formatter::new()
        .input_tab_size(*tab_size)
        .align_metadata(config.fmt.meta.align_values)
        .align_patterns(config.fmt.patterns.align_values)
        .indent_section_headers(config.fmt.rule.indent_section_headers)
        .indent_section_contents(config.fmt.rule.indent_section_contents)
        .indentation(if config.fmt.rule.indent_spaces == 0 {
            Indentation::Tabs
        } else {
            Indentation::Spaces(config.fmt.rule.indent_spaces as usize)
        })
        .newline_before_curly_brace(config.fmt.rule.newline_before_curly_brace)
        .empty_line_before_section_header(
            config.fmt.rule.empty_line_before_section_header,
        )
        .empty_line_after_section_header(
            config.fmt.rule.empty_line_after_section_header,
        );

    let mut w = walk::ParWalker::path(path);

    if let Some(num_threads) = num_threads {
        w.num_threads(*num_threads);
    }

    if let Some(filters) = filters {
        for filter in filters {
            w.filter(filter);
        }
    } else {
        // Default filters are `**/*.yar` and `**/*.yara`.
        w.filter("**/*.yar").filter("**/*.yara");
    }

    w.max_depth(*recursive.unwrap_or(&0));

    let walker_errors = Arc::new(AtomicUsize::new(0));

    let state = w
        .walk(
            FmtState::new(check),
            // Initialization
            |_, _| {},
            // Action
            |state, output, file_path, _| {
                let result = fs::read(file_path.clone())
                    .with_context(|| {
                        format!("can not read `{}`", file_path.display())
                    })
                    .and_then(|input| {
                        if state.check_mode {
                            formatter.format(input.as_slice(), io::sink())
                        } else {
                            let mut formatted =
                                Cursor::new(Vec::with_capacity(input.len()));
                            match formatter
                                .format(input.as_slice(), &mut formatted)
                            {
                                Ok(true) => {
                                    formatted.seek(SeekFrom::Start(0))?;
                                    let mut output_file =
                                        File::create(file_path.as_path())?;
                                    io::copy(
                                        &mut formatted,
                                        &mut output_file,
                                    )?;
                                    Ok(true)
                                }
                                Ok(false) => Ok(false),
                                Err(e) => Err(e),
                            }
                        }
                    });

                match result {
                    Ok(true) => {
                        state.files_modified.fetch_add(1, Ordering::Relaxed);
                        output.send(Message::Info(format!(
                            "[ {} ] {}",
                            if state.check_mode {
                                "NEED FMT".paint(Yellow).bold()
                            } else {
                                "MODIFIED".paint(Yellow).bold()
                            },
                            file_path.display()
                        )))?;
                    }
                    Ok(false) => {
                        state.files_ok.fetch_add(1, Ordering::Relaxed);
                        output.send(Message::Info(format!(
                            "[   {} ] {}",
                            "OK".paint(Green).bold(),
                            file_path.display()
                        )))?;
                    }
                    Err(err) => {
                        state.errors.fetch_add(1, Ordering::Relaxed);
                        let err_msg = if io::stdout().is_tty() {
                            err.to_string()
                        } else {
                            format!("{:#}", err)
                        };
                        output.send(Message::Info(format!(
                            "[ {} ] {}\n{}",
                            "FAIL".paint(Red).bold(),
                            file_path.display(),
                            err_msg,
                        )))?;
                    }
                };

                Ok(())
            },
            // Finalization
            |_, _| {},
            // Walk done
            |_| {},
            // Error handling
            {
                let walker_errors = walker_errors.clone();
                move |err, output| {
                    walker_errors.fetch_add(1, Ordering::Relaxed);
                    let _ = output.send(Message::Error(format!(
                        "{} {}",
                        "error:".paint(Red).bold(),
                        err
                    )));

                    Ok(())
                }
            },
        )
        .unwrap();

    // Exit code is 1 if errors were found or files were modified/need formatting.
    if state.errors.load(Ordering::Relaxed) > 0
        || walker_errors.load(Ordering::Relaxed) > 0
        || state.files_modified.load(Ordering::Relaxed) > 0
    {
        process::exit(1)
    }

    Ok(())
}

#[derive(Debug)]
struct FmtState {
    check_mode: bool,
    files_ok: AtomicUsize,
    files_modified: AtomicUsize,
    errors: AtomicUsize,
}

impl FmtState {
    fn new(check_mode: bool) -> Self {
        Self {
            check_mode,
            files_ok: AtomicUsize::new(0),
            files_modified: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
        }
    }
}

impl Component for FmtState {
    fn draw_unchecked(
        &self,
        _dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<superconsole::Lines> {
        let res = match mode {
            superconsole::DrawMode::Normal | superconsole::DrawMode::Final => {
                let ok = format!(
                    "{} file(s) ok. ",
                    self.files_ok.load(Ordering::Relaxed)
                );

                let modified = format!(
                    "{}: {}. ",
                    if self.check_mode {
                        "need formatting"
                    } else {
                        "modified"
                    },
                    self.files_modified.load(Ordering::Relaxed)
                );

                let errors = format!(
                    "errors: {}.",
                    self.errors.load(Ordering::Relaxed)
                );

                Line::from_iter([
                    Span::new_unstyled(ok.paint(Green).bold())?,
                    Span::new_unstyled(modified.paint(Yellow).bold())?,
                    Span::new_unstyled(errors.paint(Red).bold())?,
                ])
            }
        };
        Ok(Lines(vec![res]))
    }
}
