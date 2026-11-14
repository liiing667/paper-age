#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://user-images.githubusercontent.com/43314/216838549-bc5cafc8-0211-44e2-9bcc-651c74bfc853.svg"
)]
#![doc(html_favicon_url = "https://shots.matiaskorhonen.fi/paper-age-favicon.ico")]

use std::{
    env,
    fs::File,
    io::{self, stdin, BufReader, BufWriter, Write},
    path::PathBuf,
};

use age::secrecy::{ExposeSecret, SecretString};
use clap::Parser;
use paper_age::{
    builder, cli,
    encryption::{self, EncryptionError},
};
use qrcode::types::QrError;
use rpassword::prompt_password;

#[macro_use]
extern crate log;

/// Maximum length of the document title
const TITLE_MAX_LEN: usize = 64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::Args::parse();

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    if args.fonts_license {
        let license = include_bytes!("assets/fonts/IBMPlexMono-LICENSE.txt");
        io::stdout().write_all(license)?;
        return Ok(());
    }

    if args.title.len() > TITLE_MAX_LEN {
        error!(
            "The title cannot be longer than {} characters",
            TITLE_MAX_LEN
        );
        std::process::exit(exitcode::DATAERR);
    }

    let output = args.output;
    if output.exists() {
        if args.force {
            warn!("Overwriting existing output file: {}", output.display());
        } else {
            error!("Output file already exists: {}", output.display());
            std::process::exit(exitcode::CANTCREAT);
        }
    }

    let path = match args.input {
        Some(p) => p,
        None => PathBuf::from("-"),
    };
    let mut reader: BufReader<Box<dyn std::io::Read>> = {
        if path.to_string_lossy() == "-" {
            BufReader::new(Box::new(stdin().lock()))
        } else if path.is_file() {
            BufReader::new(Box::new(File::open(&path)?))
        } else {
            error!("File not found: {}", path.display());
            std::process::exit(exitcode::NOINPUT);
        }
    };

    // Read the plaintext against the shared byte budget before asking for a
    // passphrase or encrypting anything. Oversized inputs fail closed here so
    // that neither encryption nor PDF generation runs on them.
    let plaintext = match encryption::read_bounded(&mut reader, encryption::MAX_PLAINTEXT_LEN) {
        Ok(plaintext) => plaintext,
        Err(EncryptionError::InputTooLarge { length, limit }) => {
            error!(
                "Input is too large ({length} bytes). The maximum input size is {limit} bytes (~1.9 KiB)."
            );
            std::process::exit(exitcode::DATAERR);
        }
        Err(EncryptionError::Io(error)) => {
            return Err(error.into());
        }
    };

    let passphrase = get_passphrase()?;

    // Encrypt the plaintext to a ciphertext using the passphrase...
    let (plaintext_len, encrypted) =
        encryption::encrypt_plaintext(&mut plaintext.as_slice(), passphrase)?;

    info!("Plaintext length: {plaintext_len:?} bytes");
    info!("Encrypted length: {:?} bytes", encrypted.len());

    let pdf = builder::Document::new(args.title, args.page_size)?;

    let bytes = match pdf.create_pdf(args.grid, args.notes_label, args.skip_notes_line, encrypted) {
        Ok(b) => b,
        Err(error) => {
            if error.is::<QrError>() {
                error!("Too much data after encryption, please try a smaller file");
                std::process::exit(exitcode::DATAERR);
            } else {
                error!("The QR code generation failed for an unknown reason");
                std::process::exit(exitcode::SOFTWARE);
            }
        }
    };

    if output.to_string_lossy() == "-" {
        debug!("Writing to STDOUT");
        io::stdout().write_all(&bytes)?;
    } else {
        write_file_atomically(&output, &bytes)?;
    }

    Ok(())
}

/// Write `bytes` to `path` atomically.
///
/// The bytes are first written and flushed into a temporary file in the same
/// directory and then renamed over the destination. A failure while writing
/// (for example a full disk) leaves any existing file untouched and removes
/// the partial temporary file instead of truncating the old backup in place.
fn write_file_atomically(path: &PathBuf, bytes: &[u8]) -> io::Result<()> {
    debug!("Writing to file: {}", path.to_string_lossy());

    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let directory = parent.unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid output file name"))?;

    let unique = format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    );
    let temp_path = directory.join(unique);

    struct TempFileGuard {
        path: PathBuf,
    }

    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    let guard = TempFileGuard {
        path: temp_path.clone(),
    };

    {
        let file = File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(bytes)?;
        writer.into_inner()?.sync_all()?;
    }

    std::fs::rename(&temp_path, path)?;

    std::mem::forget(guard);

    Ok(())
}

/// Read a secret from the user
pub fn read_secret(prompt: &str) -> Result<SecretString, io::Error> {
    let passphrase = prompt_password(format!("{}: ", prompt)).map(SecretString::from)?;

    if passphrase.expose_secret().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passphrase can't be empty",
        ));
    }

    Ok(passphrase)
}

/// Get the passphrase from an interactive prompt or from the PAPERAGE_PASSPHRASE
/// environment variable
fn get_passphrase() -> Result<SecretString, io::Error> {
    let env_passphrase = env::var("PAPERAGE_PASSPHRASE");

    if let Ok(value) = env_passphrase {
        return Ok(SecretString::from(value));
    }

    match read_secret("Passphrase") {
        Ok(secret) => Ok(secret),
        Err(e) => Err(io::Error::other(format!("{e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use assert_fs::prelude::*;

    #[test]
    fn test_write_file_atomically_replaces_existing_file() {
        let temp = assert_fs::TempDir::new().unwrap();
        let path = temp.child("output.pdf");
        path.write_binary(b"old backup").unwrap();

        write_file_atomically(&path.to_path_buf(), b"new backup").unwrap();

        assert_eq!(std::fs::read(path.path()).unwrap(), b"new backup");

        let leftovers: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn test_write_file_atomically_keeps_old_file_on_failure() {
        let temp = assert_fs::TempDir::new().unwrap();
        let path = temp.child("output.pdf");
        path.write_binary(b"old backup").unwrap();

        // Pointing the destination at a read-only directory makes the
        // temporary file creation fail before the destination is touched.
        let readonly_dir = temp.child("readonly");
        readonly_dir.create_dir_all().unwrap();
        let mut permissions = std::fs::metadata(readonly_dir.path())
            .unwrap()
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(readonly_dir.path(), permissions).unwrap();

        let destination = readonly_dir.path().join("output.pdf");
        let result = write_file_atomically(&destination, b"new backup");
        assert!(result.is_err());

        assert_eq!(std::fs::read(path.path()).unwrap(), b"old backup");

        let leftovers: Vec<_> = std::fs::read_dir(readonly_dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn test_get_passphrase_from_env() -> Result<(), Box<dyn std::error::Error>> {
        env::set_var("PAPERAGE_PASSPHRASE", "secret");

        let result = get_passphrase();
        assert!(result.is_ok());

        let passphrase = result?;
        passphrase.expose_secret();

        assert_eq!(passphrase.expose_secret(), "secret");

        Ok(())
    }
}
