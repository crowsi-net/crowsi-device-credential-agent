use std::{
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use crate::AgentError;

pub(crate) fn id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

pub(crate) fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn hex_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn base64url(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn opaque_owner(value: &str) -> bool {
    value.starts_with("psa_")
        && (24..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

pub(crate) fn owner_file(path: &Path, expected_uid: u32) -> Result<Vec<u8>, AgentError> {
    read_file(path, expected_uid, 0o600, 262_144)
}

pub(crate) fn root_trust_file(path: &Path) -> Result<Vec<u8>, AgentError> {
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent).map_err(|_| AgentError::ConfigInvalid)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || fs::canonicalize(parent).map_err(|_| AgentError::ConfigInvalid)? != parent
        {
            return Err(AgentError::ConfigInvalid);
        }
    }
    read_file(path, 0, 0o644, 16_384).map_err(|_| AgentError::ConfigInvalid)
}

fn read_file(path: &Path, uid: u32, mode: u32, maximum: u64) -> Result<Vec<u8>, AgentError> {
    if !path.is_absolute() || fs::canonicalize(path).map_err(|_| AgentError::PathInvalid)? != path {
        return Err(AgentError::PathInvalid);
    }
    let before = fs::symlink_metadata(path).map_err(|_| AgentError::PathInvalid)?;
    valid_file(&before, uid, mode, maximum)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| AgentError::PathInvalid)?;
    let opened = file.metadata().map_err(|_| AgentError::PathInvalid)?;
    if !same(&before, &opened) {
        return Err(AgentError::PathInvalid);
    }
    let mut wire = Vec::new();
    (&file)
        .take(maximum + 1)
        .read_to_end(&mut wire)
        .map_err(|_| AgentError::PathInvalid)?;
    let after = file.metadata().map_err(|_| AgentError::PathInvalid)?;
    let path_after = fs::symlink_metadata(path).map_err(|_| AgentError::PathInvalid)?;
    if !same(&opened, &after)
        || !same(&after, &path_after)
        || !(2..=maximum as usize).contains(&wire.len())
    {
        return Err(AgentError::PathInvalid);
    }
    Ok(wire)
}

fn valid_file(value: &Metadata, uid: u32, mode: u32, maximum: u64) -> Result<(), AgentError> {
    (value.is_file()
        && !value.file_type().is_symlink()
        && value.nlink() == 1
        && value.uid() == uid
        && value.mode() & 0o777 == mode
        && (2..=maximum).contains(&value.len()))
    .then_some(())
    .ok_or(AgentError::PathInvalid)
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.nlink() == right.nlink()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}
