use assert_cmd::{cargo_bin, Command};
use assert_fs::prelude::*;
use assert_fs::TempDir;
use predicates::prelude::*;

#[test]
fn fmt() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule test { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(input_file.path())
        .assert()
        .code(1); // Exit code 1 indicates that the file was modified.

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(input_file.path())
        .assert()
        .code(0); // Second time that we format the same file, no expected changes.
}

#[test]
fn fmt_check_shows_filenames() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_str("rule test { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains("rule.yar"))
        .code(1);
}

#[test]
fn utf8_error() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_binary(&[0xff, 0xff]).unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(input_file.path())
        .assert()
        .stdout(predicate::str::contains("FAIL"))
        .stdout(predicate::str::contains("invalid UTF-8"))
        .code(1);
}

#[test]
fn fmt_directory() {
    let temp_dir = TempDir::new().unwrap();

    // Create two unformatted YARA files in the directory
    let file1 = temp_dir.child("rule1.yar");
    let file2 = temp_dir.child("rule2.yara");

    file1.write_str("rule test1 { condition: true }").unwrap();
    file2.write_str("rule test2 { condition: false }").unwrap();

    // Format the directory - should modify both files
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(temp_dir.path())
        .assert()
        .stdout(predicate::str::contains("MODIFIED"))
        .code(1);

    // Format again - should have no changes
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(temp_dir.path())
        .assert()
        .stdout(predicate::str::contains("OK"))
        .code(0);
}

#[test]
fn fmt_directory_check_mode() {
    let temp_dir = TempDir::new().unwrap();

    // Create an unformatted YARA file
    let file1 = temp_dir.child("rule1.yar");
    file1.write_str("rule test1 { condition: true }").unwrap();

    // Check mode should not modify files but report they need formatting
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--check")
        .arg(temp_dir.path())
        .assert()
        .stdout(predicate::str::contains("NEED FMT"))
        .code(1);

    // File should not have been modified (still unformatted)
    file1.assert("rule test1 { condition: true }");
}

#[test]
fn fmt_directory_with_filter() {
    let temp_dir = TempDir::new().unwrap();

    // Create files with different extensions
    // Use unique prefix to avoid glob expansion by `wild` crate on Windows
    // matching files in the repo's working directory
    let yar_file = temp_dir.child("fmttest_rule.yar");
    let txt_file = temp_dir.child("fmttest_rule.txt");

    yar_file.write_str("rule test1 { condition: true }").unwrap();
    txt_file.write_str("rule test2 { condition: true }").unwrap();

    // Format only .yar files using a pattern that won't match repo files
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--filter")
        .arg("**/fmttest_*.yar")
        .arg(temp_dir.path())
        .assert()
        .code(1); // .yar file modified

    // .txt file should not have been modified
    txt_file.assert("rule test2 { condition: true }");
}

#[test]
fn fmt_directory_recursive() {
    let temp_dir = TempDir::new().unwrap();

    // Create nested directory structure
    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();

    let root_file = temp_dir.child("root.yar");
    let nested_file = subdir.child("nested.yar");

    root_file.write_str("rule root { condition: true }").unwrap();
    nested_file.write_str("rule nested { condition: true }").unwrap();

    // Without --recursive, should only format files in root (max_depth=0)
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(temp_dir.path())
        .assert()
        .code(1); // Only root file processed

    // Reset the nested file
    nested_file.write_str("rule nested { condition: true }").unwrap();

    // Reset root file to formatted state
    root_file.write_str("rule root {\n  condition:\n    true\n}\n").unwrap();

    // With --recursive, should format files in subdirectories too
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--recursive")
        .arg(temp_dir.path())
        .assert()
        .stdout(predicate::str::contains("nested.yar"))
        .code(1); // Nested file modified
}

#[test]
fn fmt_directory_recursive_with_depth() {
    let temp_dir = TempDir::new().unwrap();

    // Create nested directory structure with multiple levels
    let level1 = temp_dir.child("level1");
    let level2 = level1.child("level2");
    level2.create_dir_all().unwrap();

    let root_file = temp_dir.child("root.yar");
    let level1_file = level1.child("level1.yar");
    let level2_file = level2.child("level2.yar");

    root_file.write_str("rule root { condition: true }").unwrap();
    level1_file.write_str("rule level1 { condition: true }").unwrap();
    level2_file.write_str("rule level2 { condition: true }").unwrap();

    // With --recursive=1, should format only root and level1
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("--recursive=1")
        .arg(temp_dir.path())
        .assert()
        .stdout(predicate::str::contains("level1.yar"))
        .code(1);

    // level2 file should still be unformatted
    level2_file.assert("rule level2 { condition: true }");
}
