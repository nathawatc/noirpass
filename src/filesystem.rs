//! Unix filesystem primitives for Noirpass-owned paths.
//!
//! Linux `openat2` resolves all components beneath an owned directory descriptor
//! with `RESOLVE_NO_SYMLINKS`. Store ciphertext mutations use pinned directory
//! descriptors. Kernels without openat2 fail closed rather than using racy opens.

use std::ffi::CString;
use std::fs::{self, File, Permissions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

/// A directory descriptor pins path operations to the opened directory even if renamed.
#[derive(Debug)]
pub(crate) struct Directory(File);

impl Directory {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        Ok(Self(open_path(
            path,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?))
    }

    pub(crate) fn child(&self, name: &Path) -> io::Result<Self> {
        Ok(Self(self.open_file(
            name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?))
    }

    pub(crate) fn open_regular(&self, name: &Path, flags: i32, mode: u32) -> io::Result<File> {
        regular_file(self.open_file(name, flags, mode)?, name)
    }

    fn ensure_linked(&self) -> io::Result<()> {
        if self.0.metadata()?.nlink() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "opened directory was removed",
            ));
        }
        Ok(())
    }

    pub(crate) fn sync_all(&self) -> io::Result<()> {
        self.ensure_linked()?;
        self.0.sync_all()
    }

    pub(crate) fn open_file(&self, name: &Path, flags: i32, mode: u32) -> io::Result<File> {
        open_beneath(&self.0, name, flags, mode)
    }

    pub(crate) fn metadata(&self, name: &Path) -> io::Result<fs::Metadata> {
        // O_PATH | O_NOFOLLOW inspects the final symlink itself, never its target.
        self.open_file(name, libc::O_PATH | libc::O_NOFOLLOW, 0)?
            .metadata()
    }

    pub(crate) fn read_dir(&self) -> io::Result<fs::ReadDir> {
        self.ensure_linked()?;
        // This deliberate procfs magic link refers to our live, owned descriptor.
        // Entry names are subsequently accessed relative to that descriptor.
        fs::read_dir(format!("/proc/self/fd/{}", self.0.as_raw_fd()))
    }

    pub(crate) fn remove(&self, name: &Path) -> io::Result<()> {
        let name = entry_name(name)?;
        // SAFETY: the directory fd and NUL-terminated name remain live for the call.
        syscall_result(unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) })
    }

    pub(crate) fn remove_directory(&self, name: &Path) -> io::Result<()> {
        let name = entry_name(name)?;
        // SAFETY: the directory fd and NUL-terminated name remain live for the call.
        syscall_result(unsafe {
            libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
        })
    }

    pub(crate) fn set_permissions(&self, permissions: Permissions) -> io::Result<()> {
        self.0.set_permissions(permissions)
    }

    fn create_child(&self, name: &Path, mode: u32) -> io::Result<Self> {
        let c_name = entry_name(name)?;
        // SAFETY: the directory fd and NUL-terminated name remain live for the call.
        if let Err(err) =
            syscall_result(unsafe { libc::mkdirat(self.0.as_raw_fd(), c_name.as_ptr(), mode) })
            && err.kind() != io::ErrorKind::AlreadyExists
        {
            return Err(err);
        }
        self.child(name)
    }

    pub(crate) fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let from = entry_name(from)?;
        let to = entry_name(to)?;
        // SAFETY: both names and the owned directory fd remain live for the call.
        syscall_result(unsafe {
            libc::renameat(
                self.0.as_raw_fd(),
                from.as_ptr(),
                self.0.as_raw_fd(),
                to.as_ptr(),
            )
        })
    }

    pub(crate) fn hard_link(&self, from: &Path, to: &Path) -> io::Result<()> {
        let from = entry_name(from)?;
        let to = entry_name(to)?;
        // SAFETY: both names and the owned directory fd remain live for the call.
        syscall_result(unsafe {
            libc::linkat(
                self.0.as_raw_fd(),
                from.as_ptr(),
                self.0.as_raw_fd(),
                to.as_ptr(),
                0,
            )
        })
    }
}

fn syscall_result(result: i32) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn entry_name(path: &Path) -> io::Result<CString> {
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected one directory entry name",
        ));
    }
    CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)
}

/// Resolve every component in the kernel; no check/open race or symlink fallback.
fn open_beneath(directory: &File, path: &Path, flags: i32, mode: u32) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: open_how contains only integer fields, for which all-zero is valid.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    let nofollow = if flags & libc::O_PATH == 0 {
        NOFOLLOW_NONBLOCK
    } else {
        libc::O_NOFOLLOW
    };
    how.flags = u64::try_from(flags | libc::O_CLOEXEC | nofollow).map_err(io::Error::other)?;
    how.mode = u64::from(mode);
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS;
    // SAFETY: pointers reference live initialized values, size matches open_how, fd is owned.
    let result = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            path.as_ptr(),
            &raw const how,
            size_of::<libc::open_how>(),
        )
    };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains symlink",
            ));
        }
        return Err(error);
    }
    let fd = i32::try_from(result).map_err(io::Error::other)?;
    // SAFETY: successful openat2 returns a new descriptor whose ownership transfers to File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_path(path: &Path, flags: i32, mode: u32) -> io::Result<File> {
    let (base, relative) = if path.is_absolute() {
        (
            File::open("/")?,
            path.strip_prefix("/").map_err(io::Error::other)?,
        )
    } else {
        (File::open(".")?, path)
    };
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    open_beneath(&base, relative, flags, mode)
}

pub(crate) fn open_regular_read_nofollow(path: &Path) -> io::Result<File> {
    regular_file(open_path(path, libc::O_RDONLY, 0)?, path)
}

pub(crate) fn open_regular_rw_nofollow(path: &Path) -> io::Result<File> {
    regular_file(open_path(path, libc::O_RDWR, 0)?, path)
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

/// Create each component relative to its opened parent, without symlink traversal.
pub(crate) fn create_directory_all_nofollow(path: &Path, mode: u32) -> io::Result<Directory> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory path escapes its root",
        ));
    }
    let mut directory = Directory::open(if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    })?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => directory = directory.create_child(Path::new(name), mode)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path escapes its root",
                ));
            }
        }
    }
    Ok(directory)
}

/// Create `path` if absent and force its permissions to `0700` through a safe directory handle.
pub(crate) fn ensure_dir_0700(path: &Path) -> io::Result<()> {
    create_directory_all_nofollow(path, 0o700)?.set_permissions(Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn directory_mutations_stay_on_pinned_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("parent");
        let moved = tmp.path().join("moved");
        let outside = tmp.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(parent.join("value"), b"owned").unwrap();
        fs::write(outside.join("value"), b"untouched").unwrap();
        let directory = Directory::open(&parent).unwrap();
        fs::rename(&parent, &moved).unwrap();
        symlink(&outside, &parent).unwrap();

        let child = directory.create_child(Path::new("child"), 0o700).unwrap();
        assert_eq!(
            child.0.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        directory.remove(Path::new("value")).unwrap();
        directory.remove_directory(Path::new("child")).unwrap();
        directory.sync_all().unwrap();

        assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
        assert_eq!(fs::read(outside.join("value")).unwrap(), b"untouched");
        assert!(!outside.join("child").exists());
        assert!(directory.remove_directory(Path::new("../outside")).is_err());
    }

    #[test]
    fn kernel_resolution_rejects_symlinks_escape_and_nonregular_files() {
        let tmp = tempfile::tempdir().unwrap();
        let owned = tmp.path().join("owned");
        let outside = tmp.path().join("outside");
        fs::create_dir(&owned).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("value"), b"untouched").unwrap();
        symlink(&outside, owned.join("link")).unwrap();
        assert!(open_regular_read_nofollow(&owned.join("link/value")).is_err());
        assert!(ensure_dir_0700(&owned.join("link/new")).is_err());
        assert!(create_directory_all_nofollow(&owned.join("../outside/new"), 0o700).is_err());
        let directory = Directory::open(&owned).unwrap();
        assert!(
            directory
                .open_file(Path::new("../outside/value"), libc::O_RDONLY, 0)
                .is_err()
        );
        assert!(
            directory
                .open_file(&outside.join("value"), libc::O_RDONLY, 0)
                .is_err()
        );
        for name in ["..", ".", "../outside/value", "/outside", ""] {
            assert!(directory.remove(Path::new(name)).is_err());
        }
        assert!(
            directory
                .rename(Path::new("link"), Path::new("../escaped"))
                .is_err()
        );
        assert!(
            directory
                .hard_link(Path::new("../outside/value"), Path::new("copy"))
                .is_err()
        );
        assert!(open_regular_read_nofollow(&owned).is_err());
        assert_eq!(fs::read(outside.join("value")).unwrap(), b"untouched");
        assert!(!outside.join("new").exists());
    }
}
