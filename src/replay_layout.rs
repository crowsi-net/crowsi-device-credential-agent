use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use crate::{
    AgentError,
    replay_file::PinnedDir,
    replay_metadata::{same, valid_file},
};

pub(super) struct Layout {
    pub state: PinnedDir,
    pub anchor: PinnedDir,
}

impl Layout {
    pub fn open(state: &Path, anchor: &Path, uid: u32) -> Result<Self, AgentError> {
        if state == anchor {
            return Err(AgentError::PathInvalid);
        }
        let value = Self {
            state: PinnedDir::open(state, uid)?,
            anchor: PinnedDir::open(anchor, uid)?,
        };
        value.verify()?;
        Ok(value)
    }
    pub fn lock(&self) -> Result<Guard<'_>, AgentError> {
        Guard::acquire(self, "ledger.lock")
    }
    pub fn execution_lock(&self) -> Result<Guard<'_>, AgentError> {
        Guard::acquire(self, "execution.lock")
    }
    pub fn verify(&self) -> Result<(), AgentError> {
        self.state.verify()?;
        self.anchor.verify()?;
        let state =
            fs::metadata(self.state.child(".")).map_err(|_| AgentError::AuthorityRollback)?;
        let anchor =
            fs::metadata(self.anchor.child(".")).map_err(|_| AgentError::AuthorityRollback)?;
        (state.dev() != anchor.dev() || state.ino() != anchor.ino())
            .then_some(())
            .ok_or(AgentError::AuthorityRollback)
    }
}

pub(super) struct Guard<'a> {
    file: File,
    layout: &'a Layout,
    name: &'static str,
}

impl<'a> Guard<'a> {
    fn acquire(layout: &'a Layout, name: &'static str) -> Result<Self, AgentError> {
        layout.verify()?;
        let path = layout.state.child(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| AgentError::AuthorityRollback)?;
        file.lock().map_err(|_| AgentError::AuthorityRollback)?;
        let guard = Self { file, layout, name };
        guard.verify()?;
        Ok(guard)
    }
    pub fn verify(&self) -> Result<(), AgentError> {
        self.layout.verify()?;
        let fd = self
            .file
            .metadata()
            .map_err(|_| AgentError::AuthorityRollback)?;
        let path = fs::symlink_metadata(self.layout.state.child(self.name))
            .map_err(|_| AgentError::AuthorityRollback)?;
        valid_file(&fd, self.layout.state.uid(), true)?;
        same(&fd, &path)
            .then_some(())
            .ok_or(AgentError::AuthorityRollback)
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

use std::os::unix::fs::MetadataExt;
