//! Unix filesystem primitives for Noirpass-owned paths.
//!
//! Path checks reject symlink components, while final file opens use
//! `O_NOFOLLOW` so reads and creates do not turn a metadata check into a
//! symlink-following operation.

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const NOFOLLOW_NONBLOCK: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK;

fn regular_file(file: File, path: &Path) -> io::Result<File> {
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path is not a regular file: {}", path.display()),
        ))
    }
}

/// Open an existing regular file for reading without following its final symlink.
pub(crate) fn open_regular_read_nofollow(path: &Path) -> io::Result<File> {
    validate_no_symlink_components(path)?;
    regular_file(
        OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW_NONBLOCK)
            .open(path)?,
        path,
    )
}

/// Open an existing regular file for read/write without following its final symlink.
pub(crate) fn open_regular_rw_nofollow(path: &Path) -> io::Result<File> {
    validate_no_symlink_components(path)?;
    regular_file(
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(NOFOLLOW_NONBLOCK)
            .open(path)?,
        path,
    )
}

/// Open or create a regular file without following its final symlink.
pub(crate) fn open_regular_rw_create_nofollow(path: &Path, mode: u32) -> io::Result<File> {
    validate_no_symlink_components(path)?;
    regular_file(
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(mode)
            .custom_flags(NOFOLLOW_NONBLOCK)
            .open(path)?,
        path,
    )
}

/// Create a new regular file without following its final symlink.
pub(crate) fn create_regular_nofollow(path: &Path, mode: u32) -> io::Result<File> {
    validate_no_symlink_components(path)?;
    regular_file(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(NOFOLLOW_NONBLOCK)
            .open(path)?,
        path,
    )
}

/// Open an existing directory without following its final symlink.
pub(crate) fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    validate_no_symlink_components(path)?;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | NOFOLLOW_NONBLOCK)
        .open(path)
}

/// Read one regular file through a no-follow descriptor.
pub(crate) fn read_regular_file_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = open_regular_read_nofollow(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Reject symlink components already present in `path`.
pub(crate) fn validate_no_symlink_components(path: &Path) -> io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => continue,
            Component::ParentDir => current.push(Path::new("..")),
            Component::Normal(name) => current.push(name),
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("path contains symlink: {}", current.display()),
                ));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => break,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Validate an existing regular file, or an absent path, without following symlinks.
pub(crate) fn validate_existing_regular_or_absent(path: &Path) -> io::Result<()> {
    validate_no_symlink_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path is not a regular file: {}", path.display()),
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Validate an existing directory, or an absent path, without following symlinks.
pub(crate) fn validate_existing_directory_or_absent(path: &Path) -> io::Result<()> {
    validate_no_symlink_components(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path is not a directory: {}", path.display()),
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Whether an entry exists, inspecting its final component without following it.
pub(crate) fn path_entry_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Create `path` if absent and force its permissions to `0700` through a safe directory handle.
pub(crate) fn ensure_dir_0700(path: &Path) -> io::Result<()> {
    validate_no_symlink_components(path)?;
    fs::create_dir_all(path)?;
    let directory = open_directory_nofollow(path)?;
    directory.set_permissions(Permissions::from_mode(0o700))?;
    Ok(())
}
