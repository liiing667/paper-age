//! Age based encryption
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::io::Write;

use age::armor::ArmoredWriter;
use age::armor::Format::AsciiArmor;
use age::secrecy::SecretString;
use log::debug;

/// Maximum accepted plaintext length in bytes.
///
/// The age ciphertext is rendered both as text and as a QR code on a single
/// page, so the plaintext cannot grow without bound. Empirically the largest
/// plaintext that still fits into a QR code is around 1950 bytes; this budget
/// stays slightly below that to leave headroom (the README advertises a
/// maximum of about 1.9 KiB).
///
/// The same budget is enforced for file inputs, standard input, and the
/// convenience library API so that oversized inputs are rejected before any
/// encryption work happens and without buffering unbounded amounts of data.
pub const MAX_PLAINTEXT_LEN: usize = 1900;

/// Errors returned while reading and encrypting the plaintext.
#[derive(Debug)]
pub enum EncryptionError {
    /// The plaintext exceeds [`MAX_PLAINTEXT_LEN`]
    InputTooLarge {
        /// Number of plaintext bytes observed before the limit was hit
        length: usize,
        /// The accepted plaintext budget in bytes
        limit: usize,
    },
    /// Reading the plaintext or performing the encryption failed
    Io(std::io::Error),
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::InputTooLarge { length, limit } => write!(
                f,
                "Input is too large ({length} bytes). The maximum input size is {limit} bytes (~1.9 KiB)."
            ),
            EncryptionError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl Error for EncryptionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EncryptionError::InputTooLarge { .. } => None,
            EncryptionError::Io(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for EncryptionError {
    fn from(error: std::io::Error) -> Self {
        EncryptionError::Io(error)
    }
}

impl From<age::EncryptError> for EncryptionError {
    fn from(error: age::EncryptError) -> Self {
        EncryptionError::Io(std::io::Error::other(error))
    }
}

impl From<std::string::FromUtf8Error> for EncryptionError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        EncryptionError::Io(std::io::Error::other(error))
    }
}

/// Read at most `limit` bytes from `reader` into a buffer.
///
/// The reader is capped to `limit + 1` bytes so that an oversized input only
/// ever occupies one byte beyond the budget in memory. If more than `limit`
/// bytes are available, [`EncryptionError::InputTooLarge`] is returned and the
/// buffered bytes are discarded.
pub fn read_bounded(
    reader: &mut dyn std::io::BufRead,
    limit: usize,
) -> Result<Vec<u8>, EncryptionError> {
    let mut plaintext = Vec::with_capacity(limit);
    let mut limited = reader.take(limit as u64 + 1);
    limited.read_to_end(&mut plaintext)?;

    if plaintext.len() > limit {
        let length = plaintext.len();
        drop(plaintext);
        return Err(EncryptionError::InputTooLarge { length, limit });
    }

    Ok(plaintext)
}

/// Encrypt the data from the reader and PEM encode the ciphertext
pub fn encrypt_plaintext(
    reader: &mut dyn std::io::BufRead,
    passphrase: SecretString,
) -> Result<(usize, String), EncryptionError> {
    debug!("Encrypting plaintext");

    let plaintext = read_bounded(reader, MAX_PLAINTEXT_LEN)?;

    let encryptor = age::Encryptor::with_user_passphrase(passphrase);

    let mut encrypted = vec![];

    let armored_writer = ArmoredWriter::wrap_output(&mut encrypted, AsciiArmor)?;

    let mut writer = encryptor.wrap_output(armored_writer)?;

    writer.write_all(&plaintext)?;

    let output = writer.finish().and_then(|armor| armor.finish())?;

    let utf8 = String::from_utf8(output.to_owned())?;

    Ok((plaintext.len(), utf8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bounded_accepts_input_up_to_the_limit() {
        let data = vec![b'a'; MAX_PLAINTEXT_LEN];
        let mut reader = &data[..];

        let plaintext = read_bounded(&mut reader, MAX_PLAINTEXT_LEN).unwrap();
        assert_eq!(plaintext.len(), MAX_PLAINTEXT_LEN);
    }

    #[test]
    fn test_read_bounded_rejects_oversized_input_without_buffering_it_all() {
        let data = vec![b'a'; MAX_PLAINTEXT_LEN + 4096];
        let mut reader = &data[..];

        let error = read_bounded(&mut reader, MAX_PLAINTEXT_LEN).unwrap_err();
        match error {
            EncryptionError::InputTooLarge { length, limit } => {
                assert_eq!(limit, MAX_PLAINTEXT_LEN);
                assert_eq!(length, MAX_PLAINTEXT_LEN + 1);
            }
            other => panic!("expected InputTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn test_encrypt_rejects_oversized_input_before_encryption() {
        let data = vec![b'x'; MAX_PLAINTEXT_LEN + 1];
        let mut reader = &data[..];
        let passphrase = SecretString::from("snakeoil".to_owned());

        let error = encrypt_plaintext(&mut reader, passphrase).unwrap_err();
        assert!(matches!(error, EncryptionError::InputTooLarge { .. }));
    }

    #[test]
    fn test_armored_output() {
        let mut input = b"some secrets" as &[u8];
        let passphrase = SecretString::from("snakeoil".to_owned());
        let result = encrypt_plaintext(&mut input, passphrase);

        assert!(result.is_ok());

        let (plaintext_size, armored) = result.unwrap();
        assert_eq!(plaintext_size, 12);

        let first_line: String = armored.lines().take(1).collect();
        assert_eq!(first_line, "-----BEGIN AGE ENCRYPTED FILE-----");

        let last_line: &str = armored.lines().last().unwrap();
        assert_eq!(last_line, "-----END AGE ENCRYPTED FILE-----")
    }
}
