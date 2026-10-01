use std::{fs::Metadata, os::unix::fs::MetadataExt};

use crate::{AgentError, replay_file::MAX_FILE_BYTES};

pub(super) fn valid_file(value: &Metadata, uid: u32, empty: bool) -> Result<(), AgentError> {
    let length = if empty {
        value.len() == 0
    } else {
        (2..=MAX_FILE_BYTES).contains(&value.len())
    };
    (value.is_file()
        && !value.file_type().is_symlink()
        && value.nlink() == 1
        && value.uid() == uid
        && value.mode() & 0o777 == 0o600
        && length)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.rdev() == b.rdev()
        && a.len() == b.len()
        && a.blocks() == b.blocks()
        && a.blksize() == b.blksize()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

pub(super) fn valid_dir(value: &Metadata, uid: u32) -> Result<(), AgentError> {
    (value.is_dir()
        && !value.file_type().is_symlink()
        && value.uid() == uid
        && value.mode() & 0o777 == 0o700)
        .then_some(())
        .ok_or(AgentError::PathInvalid)
}

pub(super) fn safe_name(name: &str) -> Result<(), AgentError> {
    (!name.is_empty()
        && name.len() <= 160
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
    .then_some(())
    .ok_or(AgentError::AuthorityRollback)
}
