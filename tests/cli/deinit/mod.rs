//! Focused CLI tests for interactive Noirpass deinitialization.
//!
//! These tests use temporary stores containing only synthetic Noirpass paths.
//! An in-process POSIX pseudo-terminal makes accepted confirmations exercise the
//! same TTY gate used by the production binary.

mod busy;
mod confirmation;
mod init_boundary;
mod preservation;
mod pty;
mod support;
