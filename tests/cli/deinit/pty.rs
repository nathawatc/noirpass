use std::ffi::{CStr, c_char, c_int};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::process::{Command, Output, Stdio};

unsafe extern "C" {
    fn posix_openpt(flags: c_int) -> c_int;
    fn grantpt(fd: c_int) -> c_int;
    fn unlockpt(fd: c_int) -> c_int;
    fn ptsname_r(fd: c_int, buffer: *mut c_char, length: usize) -> c_int;
}

pub(super) fn open_pty() -> (File, File) {
    let master_fd = unsafe { posix_openpt(0o2) };
    assert!(
        master_fd >= 0,
        "posix_openpt failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(unsafe { grantpt(master_fd) }, 0, "grantpt failed");
    assert_eq!(unsafe { unlockpt(master_fd) }, 0, "unlockpt failed");

    let mut name = [0 as c_char; 128];
    assert_eq!(
        unsafe { ptsname_r(master_fd, name.as_mut_ptr(), name.len()) },
        0,
        "ptsname_r failed"
    );
    let name = unsafe { CStr::from_ptr(name.as_ptr()) };
    let slave = OpenOptions::new()
        .read(true)
        .write(true)
        .open(name.to_str().unwrap())
        .unwrap();
    let master = unsafe { File::from_raw_fd(master_fd) };
    (master, slave)
}

pub(super) fn run_tty(store: &Path, input: &[u8]) -> Output {
    run_tty_with_input(store, input)
}

pub(super) fn run_tty_eof(store: &Path, input: &[u8]) -> Output {
    let mut input_with_eof = input.to_vec();
    input_with_eof.push(0x04);
    run_tty_with_input(store, &input_with_eof)
}

pub(super) fn run_tty_with_input(store: &Path, input: &[u8]) -> Output {
    let (mut master, slave) = open_pty();
    let child = Command::new(env!("CARGO_BIN_EXE_noirpass"))
        .env_remove("NOIRPASS_STORE")
        .arg("--store-dir")
        .arg(store)
        .arg("deinit")
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    master.write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    drop(master);
    output
}
