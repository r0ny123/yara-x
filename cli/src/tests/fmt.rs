use assert_cmd::{cargo_bin, Command};
use assert_fs::prelude::*;
use assert_fs::TempDir;

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
fn utf8_error() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.yar");

    input_file.write_binary(&[0xff, 0xff]).unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(input_file.path())
        .assert()
        .stderr("error: invalid UTF-8 at [0..1]\n")
        .code(1);
}

#[test]
fn fmt_dir() {
    let temp_dir = TempDir::new().unwrap();
    let subdir = temp_dir.child("subdir");
    subdir.create_dir_all().unwrap();
    let input_file = subdir.child("rule.yar");

    input_file.write_str("rule test { condition: true }").unwrap();

    // Default depth is 0, so it shouldn't reach the file in the subdirectory.
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(temp_dir.path())
        .assert()
        .code(0);

    // With recursive search, it should reach the file.
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("-r")
        .arg(temp_dir.path())
        .assert()
        .code(1); // Modified

    // Run again, should be clean.
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg("-r")
        .arg(temp_dir.path())
        .assert()
        .code(0);

    // Reset file
    input_file.write_str("rule test { condition: true }").unwrap();

    // Passing the subdirectory directly should also work.
    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(subdir.path())
        .assert()
        .code(1); // Modified
}

#[test]
fn fmt_explicit_file_without_extension() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.child("rule.txt");

    input_file.write_str("rule test { condition: true }").unwrap();

    Command::new(cargo_bin!("yr"))
        .arg("fmt")
        .arg(input_file.path())
        .assert()
        .code(1); // Should format it.
}
