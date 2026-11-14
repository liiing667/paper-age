#![cfg(feature = "cli")]

use assert_cmd::cargo::cargo_bin_cmd;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn test_happy_path() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();
    let input = temp.child("sample.txt");
    input.write_str("Hello")?;
    let output = temp.child("output.pdf");
    let mut cmd = cargo_bin_cmd!("paper-age");

    cmd.arg("--output")
        .arg(output.path())
        .arg("--grid")
        .arg(input.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    cmd.assert().success();

    output.assert(predicate::path::is_file());

    Ok(())
}

#[test]
fn test_letter_support() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();
    let input = temp.child("sample.txt");
    input.write_str("Hello")?;
    let output = temp.child("letter.pdf");
    let mut cmd = cargo_bin_cmd!("paper-age");

    cmd.arg("--output")
        .arg(output.path())
        .arg("--page-size")
        .arg("letter")
        .arg(input.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    cmd.assert().success();

    output.assert(predicate::path::is_file());

    Ok(())
}

#[test]
fn test_stdout() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();
    let input = temp.child("sample.txt");
    input.write_str("STDOUT")?;

    let mut cmd = cargo_bin_cmd!("paper-age");

    let output_size = 50 * 1024; // 50 KiB
    let len_predicate_fn = predicate::function(|x: &[u8]| x.len() > output_size);

    cmd.arg("--output")
        .arg("-")
        .arg(input.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    cmd.assert().stdout(len_predicate_fn).success();

    Ok(())
}

#[test]
fn test_file_doesnt_exist() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();
    let output = temp.child("output.pdf");
    let mut cmd = cargo_bin_cmd!("paper-age");

    cmd.arg("--output")
        .arg(output.path())
        .arg("test/file/doesnt/exist");
    cmd.assert().failure().stderr(predicate::str::contains(
        "File not found: test/file/doesnt/exist",
    ));

    output.assert(predicate::path::missing());

    Ok(())
}

#[test]
fn test_too_much_data() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();
    let input = temp.child("sample.txt");
    input.write_str("x".repeat(1901).as_str())?;
    let output = temp.child("output.pdf");
    let mut cmd = cargo_bin_cmd!("paper-age");

    cmd.arg("--output")
        .arg(output.path())
        .arg(input.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Input is too large"));

    output.assert(predicate::path::missing());

    Ok(())
}

#[test]
fn test_too_much_data_on_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();
    let output = temp.child("output.pdf");
    let mut cmd = cargo_bin_cmd!("paper-age");

    cmd.arg("--output")
        .arg(output.path())
        .write_stdin("x".repeat(1901))
        .env("PAPERAGE_PASSPHRASE", "secret");
    cmd.assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Input is too large"));

    output.assert(predicate::path::missing());

    Ok(())
}

#[test]
fn test_maximum_sized_input_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();
    let input = temp.child("sample.txt");
    input.write_str("x".repeat(1900).as_str())?;
    let output = temp.child("output.pdf");
    let mut cmd = cargo_bin_cmd!("paper-age");

    cmd.arg("--output")
        .arg(output.path())
        .arg(input.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    cmd.assert().success();

    output.assert(predicate::path::is_file());

    Ok(())
}

#[test]
fn test_force_keeps_old_output_on_failure() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();

    // Create an initial, valid backup.
    let input = temp.child("sample.txt");
    input.write_str("Hello")?;
    let output = temp.child("output.pdf");
    let mut first = cargo_bin_cmd!("paper-age");
    first
        .arg("--output")
        .arg(output.path())
        .arg(input.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    first.assert().success();

    let original = std::fs::read(output.path())?;
    assert!(!original.is_empty());

    // A second run that fails must leave the existing backup byte-for-byte
    // intact and must not leave any temporary files behind.
    let oversized = temp.child("oversized.txt");
    oversized.write_str("x".repeat(1901).as_str())?;
    let mut second = cargo_bin_cmd!("paper-age");
    second
        .arg("--force")
        .arg("--output")
        .arg(output.path())
        .arg(oversized.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    second
        .assert()
        .failure()
        .stderr(predicate::str::contains("Input is too large"));

    output.assert(predicate::path::is_file());
    assert_eq!(std::fs::read(output.path())?, original);

    let leftovers: Vec<_> = std::fs::read_dir(temp.path())?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name())
        .filter(|name| name.to_string_lossy().contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary files left behind: {leftovers:?}"
    );

    Ok(())
}

#[test]
fn test_force_atomically_replaces_output_on_success() -> Result<(), Box<dyn std::error::Error>> {
    let temp = assert_fs::TempDir::new().unwrap();

    let first_input = temp.child("first.txt");
    first_input.write_str("first backup")?;
    let output = temp.child("output.pdf");
    let mut first = cargo_bin_cmd!("paper-age");
    first
        .arg("--output")
        .arg(output.path())
        .arg(first_input.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    first.assert().success();

    let second_input = temp.child("second.txt");
    second_input.write_str("second backup")?;
    let mut second = cargo_bin_cmd!("paper-age");
    second
        .arg("--force")
        .arg("--output")
        .arg(output.path())
        .arg(second_input.path())
        .env("PAPERAGE_PASSPHRASE", "secret");
    second.assert().success();

    output.assert(predicate::path::is_file());
    let replaced = std::fs::read(output.path())?;
    assert!(!replaced.is_empty());

    let leftovers: Vec<_> = std::fs::read_dir(temp.path())?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name())
        .filter(|name| name.to_string_lossy().contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary files left behind: {leftovers:?}"
    );

    Ok(())
}

#[test]
fn test_fonts_license() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = cargo_bin_cmd!("paper-age");

    cmd.arg("--fonts-license");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("SIL OPEN FONT LICENSE"));

    Ok(())
}

#[test]
fn test_title_too_long() -> Result<(), Box<dyn std::error::Error>> {
    let input = assert_fs::NamedTempFile::new("sample.txt")?;
    let mut cmd = cargo_bin_cmd!("paper-age");

    cmd.arg("--title").arg("x".repeat(80)).arg(input.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("The title cannot be longer than"));

    Ok(())
}
