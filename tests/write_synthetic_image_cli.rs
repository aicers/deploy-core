//! The `write_synthetic_image` example's logic, driven in memory through the
//! `cli` module the example's `main` wraps. No test locates or runs a built
//! example binary.

#[path = "../examples/write_synthetic_image/cli.rs"]
mod cli;

use std::path::Path;

use deploy_core::image::ImageDeclaration;

const REF: &str = "registry.example/synthetic/sample:1.0";

/// Runs the example with `args`, returning its exit code and what it wrote to
/// stdout and stderr.
fn run(args: &[&str]) -> (u8, String, String) {
    let args: Vec<String> = args.iter().map(ToString::to_string).collect();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = cli::run(&args, &mut stdout, &mut stderr);
    (
        code,
        String::from_utf8(stdout).expect("the example writes UTF-8 to stdout"),
        String::from_utf8(stderr).expect("the example writes UTF-8 to stderr"),
    )
}

fn path(dir: &Path, name: &str) -> String {
    dir.join(name)
        .to_str()
        .expect("a temporary directory path is UTF-8")
        .to_string()
}

#[test]
fn written_output_is_classified_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let archive = path(dir.path(), "sample.tar");
    let declaration = path(dir.path(), "sample.declaration.json");
    let (code, stdout, stderr) = run(&["write", &archive, &declaration, "arm64", REF, "sample:2"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "");

    let written: ImageDeclaration =
        serde_json::from_slice(&std::fs::read(&declaration).unwrap()).unwrap();
    written.validate().unwrap();
    assert_eq!(written.public_refs, [REF, "sample:2"]);

    let (code, stdout, stderr) = run(&["classify", &archive, &declaration]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout, "accepted\n");
}

#[test]
fn a_mismatched_declaration_is_refused_with_code_one() {
    let dir = tempfile::tempdir().unwrap();
    let archive = path(dir.path(), "sample.tar");
    let declaration = path(dir.path(), "sample.declaration.json");
    assert_eq!(run(&["write", &archive, &declaration, "amd64", REF]).0, 0);

    let mut other: ImageDeclaration =
        serde_json::from_slice(&std::fs::read(&declaration).unwrap()).unwrap();
    other.public_refs = vec!["registry.example/synthetic/sample:other".to_string()];
    let other_path = path(dir.path(), "other.declaration.json");
    std::fs::write(&other_path, serde_json::to_vec(&other).unwrap()).unwrap();

    let (code, stdout, _) = run(&["classify", &archive, &other_path]);
    assert_eq!(code, 1);
    assert!(
        stdout.contains(&format!("image archive `{archive}`")),
        "{stdout}"
    );
    assert!(
        stdout.contains("registry.example/synthetic/sample"),
        "{stdout}"
    );
}

#[test]
fn usage_errors_exit_with_code_two_on_stderr_only() {
    let dir = tempfile::tempdir().unwrap();
    let archive = path(dir.path(), "sample.tar");
    let declaration = path(dir.path(), "sample.declaration.json");
    for args in [
        &[][..],
        &["write", &archive, &declaration, "riscv64", REF][..],
        &["frobnicate"][..],
    ] {
        let (code, stdout, stderr) = run(args);
        assert_eq!(code, 2, "{args:?}");
        assert_eq!(stdout, "", "{args:?}");
        assert!(stderr.contains("usage:"), "{args:?}: {stderr}");
    }
    assert!(!Path::new(&archive).exists());
}

#[test]
fn a_missing_file_is_an_io_error_with_code_two() {
    let dir = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run(&[
        "classify",
        &path(dir.path(), "absent.tar"),
        &path(dir.path(), "absent.declaration.json"),
    ]);
    assert_eq!(code, 2);
    assert_eq!(stdout, "");
    assert!(stderr.contains("absent.declaration.json"), "{stderr}");
}
