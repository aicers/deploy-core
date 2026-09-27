//! Writes the signed format-6 package fixture whose images verify in full.
//!
//! ```text
//! write_signed_v6_fixture <dir>
//! ```
//!
//! Builds a Compose file and two canonical synthetic images — a normalized
//! third-party database under its canonical runtime alias and a product-built
//! web image under its own tag — for `example-app` 1.0.0 in
//! `example-product`, then prepares, signs and finalizes them through
//! `package::prepare_sign_finalize` under a freshly minted Ed25519 key. It
//! writes `package.pkg` and `public-key.hex` into `<dir>`, which must exist
//! and not already hold a `package.pkg`, discards the private key, and prints
//! each image's archive path and the manifest digest its archive carries.
//! Build it with `--features test-support`.

use std::path::Path;
use std::process::ExitCode;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use deploy_core::package::{ContentLimits, prepare_sign_finalize};
use deploy_core::payload::Signed;
use deploy_core::verify::{TrustAnchor, TrustSet, key_id};

mod fixture;

use fixture::Failure;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [dir] => write(Path::new(dir)),
        _ => Err("usage: write_signed_v6_fixture <dir>".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn write(dir: &Path) -> Result<(), Failure> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "key generation failed")?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| "the key does not parse")?;
    let public: [u8; 32] = pair.public_key().as_ref().try_into()?;
    let trust = TrustSet::new(vec![TrustAnchor::new(public, false)], Vec::new(), 0, 0)?;

    let sources = tempfile::tempdir()?;
    let members = fixture::members()?;
    let inputs = fixture::inputs(&members, sources.path())?;
    let staging = tempfile::tempdir()?;
    // Preparation refuses a staging parent reached through a symlink, such
    // as macOS's `/var`.
    let staging_parent = std::fs::canonicalize(staging.path())?;
    let finalized = prepare_sign_finalize(
        &inputs,
        None,
        None,
        &fixture::request()?,
        fixture::TARGET,
        &ContentLimits::default(),
        &staging_parent,
        &trust,
        |manifest| {
            Ok(Signed {
                signature: pair.sign(manifest).as_ref().to_vec(),
                key_id: key_id(&public),
            })
        },
    )?;
    // Publication takes only an absolute destination without symlinks.
    let dir = std::fs::canonicalize(dir)?;
    finalized.publish(&dir.join("package.pkg"))?;

    let hex = public.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    });
    std::fs::write(dir.join("public-key.hex"), hex)?;
    for member in &members {
        if let Some(digest) = &member.manifest_digest {
            println!("{} {digest}", member.archive_path);
        }
    }
    Ok(())
}
