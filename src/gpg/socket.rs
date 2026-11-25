//! Locate an existing Linux `GnuPG` agent without running `gpgconf` or launching it.
//!
//! Standard runtime socket layouts follow `GnuPG`'s `common/homedir.c`:
//! <https://github.com/gpg/gnupg/blob/master/common/homedir.c>
//! Non-default homes use the first 120 SHA-1 bits, encoded with z-base-32.
//! SHA-1 here identifies a directory; it provides no security decision.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use sequoia_openpgp::types::HashAlgorithm;

use crate::error::{Error, Result};

use super::cert::pgp_err;

fn account_home(user: Option<&[u8]>) -> Result<Option<OsString>> {
    let name = user
        .map(CString::new)
        .transpose()
        .map_err(|err| Error::OpenPgp(format!("invalid account name: {err}")))?;
    let mut buffer = vec![0_u8; 1024];
    loop {
        let mut account = MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: both reentrant lookups write only into this account and buffer.
        // The optional name is NUL-terminated and all pointers remain live.
        let error = unsafe {
            if let Some(name) = &name {
                libc::getpwnam_r(
                    name.as_ptr(),
                    account.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &raw mut found,
                )
            } else {
                libc::getpwuid_r(
                    libc::getuid(),
                    account.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &raw mut found,
                )
            }
        };
        if error == libc::ERANGE {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error).into());
        }
        if found.is_null() {
            return Ok(None);
        }
        // SAFETY: POSIX getpwnam_r/getpwuid_r writes the passwd record into
        // `account` when returning success with a non-null result pointer.
        let account = unsafe { account.assume_init() };
        let directory = account.pw_dir;
        if directory.is_null() {
            return Ok(None);
        }
        // SAFETY: pw_dir is NUL-terminated inside the still-live lookup buffer.
        let directory = unsafe { CStr::from_ptr(directory) }.to_bytes().to_vec();
        return Ok(Some(OsString::from_vec(directory)));
    }
}

fn normalize_home(home: &Path, user_home: Option<&OsStr>) -> Result<PathBuf> {
    // GnuPG strips trailing slashes, expands tildes and prefixes relative paths.
    // Do not canonicalize: absolute dots, repeated slashes and symlinks affect its hash.
    let mut home = home.as_os_str().as_bytes().to_vec();
    while home.len() > 1 && home.last() == Some(&b'/') {
        home.pop();
    }
    if home.starts_with(b"~") {
        let end = home
            .iter()
            .position(|byte| *byte == b'/')
            .unwrap_or(home.len());
        let directory = if end == 1 {
            match user_home {
                Some(home) => Some(home.to_os_string()),
                None => account_home(None)?,
            }
        } else {
            account_home(Some(&home[1..end]))?
        };
        // GnuPG leaves an unknown user's tilde expression unchanged.
        if let Some(directory) = directory {
            let mut expanded = directory.into_vec();
            expanded.extend_from_slice(&home[end..]);
            home = expanded;
        }
    }
    if !home.starts_with(b"/") {
        let mut absolute = std::env::current_dir()?.into_os_string().into_vec();
        if absolute != b"/" {
            absolute.push(b'/');
        }
        absolute.extend_from_slice(&home);
        // GnuPG removes a final /. only when making a relative path absolute.
        if absolute.len() > 2 && absolute.ends_with(b"/.") {
            absolute.truncate(absolute.len() - 2);
        }
        home = absolute;
    }
    Ok(PathBuf::from(OsString::from_vec(home)))
}

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
    let user_home = std::env::var_os("HOME");
    let default_home = normalize_home(Path::new("~/.gnupg"), user_home.as_deref())?;
    let home = homedir
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("GNUPGHOME")
                .filter(|home| !home.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| default_home.clone());
    let home = normalize_home(&home, user_home.as_deref())?;
    let non_default = default_home.as_os_str() != home.as_os_str();
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
    fn home_normalization_preserves_gnupg_hash_spelling() {
        for (input, expected) in [
            ("/tmp/gnupg///", "/tmp/gnupg"),
            ("/tmp/gnupg/./", "/tmp/gnupg/."),
            ("/tmp//gnupg", "/tmp//gnupg"),
            ("/tmp/link/../gnupg", "/tmp/link/../gnupg"),
            ("~/gnupg/", "/tmp/user/gnupg"),
            ("~", "/tmp/user"),
            ("///", "/"),
        ] {
            let actual = normalize_home(Path::new(input), Some(OsStr::new("/tmp/user"))).unwrap();
            assert_eq!(actual.as_os_str().as_bytes(), expected.as_bytes());
        }
        let actual = normalize_home(Path::new("./gnupg/."), None).unwrap();
        let expected = std::env::current_dir().unwrap().join("./gnupg");
        assert_eq!(
            actual.as_os_str().as_bytes(),
            expected.as_os_str().as_bytes()
        );
        let actual = normalize_home(Path::new("."), None).unwrap();
        assert_eq!(actual, std::env::current_dir().unwrap());
    }

    #[test]
    fn tilde_expansion_uses_accounts_for_named_users_and_missing_home() {
        let mut buffer = vec![0_u8; 1024];
        let mut account = MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        loop {
            // SAFETY: the reentrant lookup owns its record and backing buffer.
            let error = unsafe {
                libc::getpwuid_r(
                    libc::getuid(),
                    account.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &raw mut found,
                )
            };
            if error == libc::ERANGE {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }
            assert_eq!(error, 0);
            assert!(!found.is_null());
            break;
        }
        // SAFETY: the successful lookup initializes `account` with NUL-terminated
        // fields backed by `buffer`, which remains live until both fields are copied.
        let account = unsafe { account.assume_init() };
        let (name, directory) = unsafe {
            (
                CStr::from_ptr(account.pw_name).to_bytes().to_vec(),
                CStr::from_ptr(account.pw_dir).to_bytes().to_vec(),
            )
        };
        let mut named = b"~".to_vec();
        named.extend_from_slice(&name);
        named.extend_from_slice(b"/gnupg/.");
        let mut expected = directory.clone();
        expected.extend_from_slice(b"/gnupg/.");
        for (input, home) in [
            (
                Path::new(OsStr::from_bytes(&named)),
                Some(OsStr::new("/ignored")),
            ),
            (Path::new("~/gnupg/."), None),
        ] {
            let actual = normalize_home(input, home).unwrap();
            assert_eq!(actual.as_os_str().as_bytes(), expected);
        }
        let actual = normalize_home(Path::new("~"), None).unwrap();
        assert_eq!(actual.as_os_str().as_bytes(), directory);
        assert!(account_home(Some(b"invalid\0account")).is_err());

        // A name longer than any login name cannot resolve to an ambient account.
        let missing = format!("~{}/gnupg", "noirpass-fixture-".repeat(32));
        let actual = normalize_home(Path::new(&missing), None).unwrap();
        let expected = std::env::current_dir().unwrap().join(&missing);
        assert_eq!(
            actual.as_os_str().as_bytes(),
            expected.as_os_str().as_bytes()
        );
    }

    #[test]
    fn runtime_suffix_matches_gnupg_120_bit_zbase32_layout() {
        assert_eq!(
            runtime_suffix(Path::new("/tmp/noirpass-gnupg")).unwrap(),
            "d.8xpqezmdg49dkr69otcqwr4w"
        );
    }
}
