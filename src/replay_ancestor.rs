use std::{
    fs::{self, File, Metadata, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use crate::AgentError;

pub(super) struct PinnedAncestor {
    path: PathBuf,
    file: File,
}

impl PinnedAncestor {
    pub(super) fn open_all(path: &Path, uid: u32) -> Result<Vec<Self>, AgentError> {
        let mut paths: Vec<_> = path.ancestors().skip(1).collect();
        paths.reverse();
        let values = paths
            .into_iter()
            .map(|path| Self::open(path, uid))
            .collect::<Result<Vec<_>, _>>()?;
        for value in &values {
            value.verify(uid)?;
        }
        Ok(values)
    }

    fn open(path: &Path, uid: u32) -> Result<Self, AgentError> {
        let before = fs::symlink_metadata(path).map_err(|_| AgentError::PathInvalid)?;
        valid(&before, uid)?;
        if fs::canonicalize(path).ok().as_deref() != Some(path) {
            return Err(AgentError::PathInvalid);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| AgentError::PathInvalid)?;
        let opened = file.metadata().map_err(|_| AgentError::PathInvalid)?;
        if !same(&before, &opened) {
            return Err(AgentError::PathInvalid);
        }
        Ok(Self {
            path: path.into(),
            file,
        })
    }

    pub(super) fn verify(&self, uid: u32) -> Result<(), AgentError> {
        let descriptor = self
            .file
            .metadata()
            .map_err(|_| AgentError::AuthorityRollback)?;
        let path = fs::symlink_metadata(&self.path).map_err(|_| AgentError::AuthorityRollback)?;
        valid(&descriptor, uid).map_err(|_| AgentError::AuthorityRollback)?;
        if fs::canonicalize(&self.path).ok().as_deref() != Some(self.path.as_path())
            || !same(&descriptor, &path)
        {
            return Err(AgentError::AuthorityRollback);
        }
        Ok(())
    }
}

fn valid(value: &Metadata, uid: u32) -> Result<(), AgentError> {
    (value.is_dir()
        && !value.file_type().is_symlink()
        && (value.uid() == 0 || value.uid() == uid)
        && value.mode() & 0o022 == 0)
        .then_some(())
        .ok_or(AgentError::PathInvalid)
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.rdev() == right.rdev()
}
