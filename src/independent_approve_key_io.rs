use nix::{
    fcntl::{AtFlags, OFlag, openat},
    sys::stat::{FileStat, Mode, SFlag, fstat, fstatat},
    unistd::{close, read as fd_read},
};
use std::{
    fs::{self, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

use crate::AgentError;

const MAXIMUM_BYTES: usize = 4_096;

struct Descriptor(i32);

impl Drop for Descriptor {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

pub(super) fn read(path: &str, uid: u32) -> Result<Vec<u8>, AgentError> {
    let path = Path::new(path);
    let parent = path.parent().ok_or(AgentError::PathInvalid)?;
    let name = path.file_name().ok_or(AgentError::PathInvalid)?;
    if !path.is_absolute()
        || fs::canonicalize(parent).map_err(|_| AgentError::PathInvalid)? != parent
    {
        return Err(AgentError::PathInvalid);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| AgentError::PathInvalid)?;
    let named_directory =
        fstatat(None, parent, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| AgentError::PathInvalid)?;
    let opened_directory = fstat(directory.as_raw_fd()).map_err(|_| AgentError::PathInvalid)?;
    valid_directory(&opened_directory, uid)?;
    if !same(&named_directory, &opened_directory) {
        return Err(AgentError::PathInvalid);
    }
    let before = fstatat(
        Some(directory.as_raw_fd()),
        name,
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|_| AgentError::PathInvalid)?;
    valid(&before, uid)?;
    let descriptor = Descriptor(
        openat(
            Some(directory.as_raw_fd()),
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| AgentError::PathInvalid)?,
    );
    let opened = fstat(descriptor.0).map_err(|_| AgentError::PathInvalid)?;
    if !same(&before, &opened) {
        return Err(AgentError::PathInvalid);
    }
    let expected = usize::try_from(opened.st_size).map_err(|_| AgentError::PathInvalid)?;
    let mut wire = vec![0_u8; expected];
    let mut offset = 0;
    while offset < wire.len() {
        let count =
            fd_read(descriptor.0, &mut wire[offset..]).map_err(|_| AgentError::PathInvalid)?;
        if count == 0 {
            return Err(AgentError::PathInvalid);
        }
        offset += count;
    }
    let mut trailing = [0_u8; 1];
    if fd_read(descriptor.0, &mut trailing).map_err(|_| AgentError::PathInvalid)? != 0 {
        return Err(AgentError::PathInvalid);
    }
    let after = fstat(descriptor.0).map_err(|_| AgentError::PathInvalid)?;
    let path_after = fstatat(
        Some(directory.as_raw_fd()),
        name,
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|_| AgentError::PathInvalid)?;
    let directory_after = fstat(directory.as_raw_fd()).map_err(|_| AgentError::PathInvalid)?;
    let named_directory_after =
        fstatat(None, parent, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| AgentError::PathInvalid)?;
    (same(&opened, &after)
        && same(&after, &path_after)
        && same(&opened_directory, &directory_after)
        && same(&directory_after, &named_directory_after))
    .then_some(wire)
    .ok_or(AgentError::PathInvalid)
}

fn valid_directory(value: &FileStat, uid: u32) -> Result<(), AgentError> {
    let kind = SFlag::from_bits_truncate(value.st_mode);
    (kind.contains(SFlag::S_IFDIR) && value.st_uid == uid && value.st_mode & 0o777 == 0o700)
        .then_some(())
        .ok_or(AgentError::PathInvalid)
}

fn valid(value: &FileStat, uid: u32) -> Result<(), AgentError> {
    let kind = SFlag::from_bits_truncate(value.st_mode);
    (kind.contains(SFlag::S_IFREG)
        && value.st_nlink == 1
        && value.st_uid == uid
        && value.st_mode & 0o777 == 0o600
        && (2..=MAXIMUM_BYTES as i64).contains(&value.st_size))
    .then_some(())
    .ok_or(AgentError::PathInvalid)
}

fn same(left: &FileStat, right: &FileStat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_size == right.st_size
        && left.st_nlink == right.st_nlink
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}
