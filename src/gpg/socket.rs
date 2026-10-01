//! Locate an existing Linux `GnuPG` agent without running `gpgconf` or launching it.
//!
//! Standard runtime socket layouts follow `GnuPG`'s `common/homedir.c`:
//! <https://github.com/gpg/gnupg/blob/master/common/homedir.c>
//! Non-default homes use the first 120 SHA-1 bits, encoded with z-base-32.
//! SHA-1 here identifies a directory; it provides no security decision.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use sequoia_openpgp::types::HashAlgorithm;

use crate::error::{Error, Result};

use super::cert::pgp_err;

fn runtime_suffix(home: &Path) -> Result<String> {
    const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    let mut hash = HashAlgorithm::SHA1.context().map_err(pgp_err)?.for_digest();
    hash.update(home.as_os_str().as_bytes());
    let digest = hash.into_digest().map_err(pgp_err)?;
    let mut suffix = String::from("d.");
    // Each five-bit group spans byte boundaries; 120 bits produce 24 characters.
    for bit in (0..120).step_by(5) {
        let byte = bit / 8;
        let shift = bit % 8;
        let pair = (u16::from(digest[byte]) << 8) | u16::from(digest[byte + 1]);
        suffix.push(char::from(
            ALPHABET[usize::from((pair >> (11 - shift)) & 31)],
        ));
    }
    Ok(suffix)
}

pub(super) fn agent_socket(homedir: Option<&Path>) -> Result<PathBuf> {
    let default_home = std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".gnupg"));
    let home = homedir
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("GNUPGHOME")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| default_home.clone())
        .ok_or_else(|| Error::OpenPgp("neither GNUPGHOME nor HOME is set".into()))?;
    let home = std::path::absolute(home)?;
    let non_default = default_home
        .as_ref()
        .map(std::path::absolute)
        .transpose()?
        .as_ref()
        != Some(&home);
    let suffix = if non_default {
        Some(runtime_suffix(&home)?)
    } else {
        None
    };
    // GnuPG deliberately ignores XDG_RUNTIME_DIR. Only probe sockets belonging
    // to this home; never enumerate or connect to other homes' agents.
    let uid = unsafe { libc::getuid() };
    for base in ["/run/gnupg", "/run", "/var/run/gnupg", "/var/run"] {
        let mut directory = PathBuf::from(base).join(format!("user/{uid}/gnupg"));
        if let Some(suffix) = &suffix {
            directory.push(suffix);
        }
        if let Ok(metadata) = std::fs::metadata(&directory)
            && metadata.is_dir()
            && metadata.uid() == uid
            && metadata.mode().trailing_zeros() >= 6
        {
            let socket = directory.join("S.gpg-agent");
            if std::fs::metadata(&socket).is_ok_and(|metadata| metadata.file_type().is_socket()) {
                return Ok(socket);
            }
        }
    }
    // Older GnuPG and systems without runtime directories keep sockets at home.
    Ok(home.join("S.gpg-agent"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_suffix_matches_gnupg_120_bit_zbase32_layout() {
        assert_eq!(
            runtime_suffix(Path::new("/tmp/noirpass-gnupg")).unwrap(),
            "d.8xpqezmdg49dkr69otcqwr4w"
        );
    }
}
