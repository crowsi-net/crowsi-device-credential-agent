use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

use crate::{
    AgentError,
    replay_ancestor::PinnedAncestor,
    replay_metadata::{same, valid_dir, valid_file},
};

pub(super) const MAX_FILE_BYTES: u64 = 524_288;

pub(super) struct PinnedDir {
    pub(super) path: PathBuf,
    pub(super) file: File,
    pub(super) uid: u32,
    ancestors: Vec<PinnedAncestor>,
}

impl PinnedDir {
    pub fn open(path: &Path, uid: u32) -> Result<Self, AgentError> {
        if !path.is_absolute() || fs::canonicalize(path).ok().as_deref() != Some(path) {
            return Err(AgentError::PathInvalid);
        }
        let ancestors = PinnedAncestor::open_all(path, uid)?;
        let before = fs::symlink_metadata(path).map_err(|_| AgentError::PathInvalid)?;
        valid_dir(&before, uid)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| AgentError::PathInvalid)?;
        let opened = file.metadata().map_err(|_| AgentError::PathInvalid)?;
        if !same(&before, &opened) {
            return Err(AgentError::PathInvalid);
        }
        let value = Self {
            path: path.to_owned(),
            file,
            uid,
            ancestors,
        };
        value.verify().map_err(|_| AgentError::PathInvalid)?;
        Ok(value)
    }
    pub fn verify(&self) -> Result<(), AgentError> {
        for ancestor in &self.ancestors {
            ancestor.verify(self.uid)?;
        }
        if fs::canonicalize(&self.path).ok().as_deref() != Some(self.path.as_path()) {
            return Err(AgentError::AuthorityRollback);
        }
        let fd = self
            .file
            .metadata()
            .map_err(|_| AgentError::AuthorityRollback)?;
        let path = fs::symlink_metadata(&self.path).map_err(|_| AgentError::AuthorityRollback)?;
        valid_dir(&fd, self.uid).map_err(|_| AgentError::AuthorityRollback)?;
        same(&fd, &path)
            .then_some(())
            .ok_or(AgentError::AuthorityRollback)
    }
    pub fn names(&self) -> Result<Vec<String>, AgentError> {
        self.verify()?;
        let mut names = Vec::new();
        for entry in fs::read_dir(self.proc_path()).map_err(|_| AgentError::AuthorityRollback)? {
            let name = entry
                .map_err(|_| AgentError::AuthorityRollback)?
                .file_name()
                .into_string()
                .map_err(|_| AgentError::AuthorityRollback)?;
            if name.len() > 160 || names.len() >= 20 {
                return Err(AgentError::AuthorityRollback);
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
    pub fn read(&self, name: &str) -> Result<Vec<u8>, AgentError> {
        crate::replay_metadata::safe_name(name)?;
        let path = self.child(name);
        let before = fs::symlink_metadata(&path).map_err(|_| AgentError::AuthorityRollback)?;
        valid_file(&before, self.uid, false)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| AgentError::AuthorityRollback)?;
        let opened = file.metadata().map_err(|_| AgentError::AuthorityRollback)?;
        if !same(&before, &opened) {
            return Err(AgentError::AuthorityRollback);
        }
        let mut wire = Vec::new();
        (&file)
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut wire)
            .map_err(|_| AgentError::AuthorityRollback)?;
        let after = file.metadata().map_err(|_| AgentError::AuthorityRollback)?;
        let path_after = fs::symlink_metadata(&path).map_err(|_| AgentError::AuthorityRollback)?;
        valid_file(&after, self.uid, false)?;
        if !same(&after, &path_after) || wire.len() as u64 != after.len() {
            return Err(AgentError::AuthorityRollback);
        }
        Ok(wire)
    }
    pub fn child(&self, name: &str) -> PathBuf {
        self.proc_path().join(name)
    }
    pub(super) fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
}
