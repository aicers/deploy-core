//! Writes a synthetic image archive with its declaration, or classifies an
//! image archive against a declaration.
//!
//! ```text
//! write_synthetic_image write <out.tar> <out.declaration.json> <amd64|arm64> <ref>...
//! write_synthetic_image classify <archive.tar> <declaration.json>
//! ```
//!
//! Exits 0 on success or `accepted`, 1 when the classifier refuses the
//! archive, and 2 for a usage error or an I/O error on a named file. Build it
//! with `--features test-support`.

use std::process::ExitCode;

mod cli;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = cli::run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    ExitCode::from(code)
}
