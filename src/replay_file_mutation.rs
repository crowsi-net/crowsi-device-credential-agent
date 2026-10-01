use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use crate::{
    AgentError,
    replay_file::{MAX_FILE_BYTES, PinnedDir},
    replay_metadata::{same, valid_file},
    replay_record::digest_hex,
};

impl PinnedDir {
    pub fn create(&self, name: &str, wire: &[u8]) -> Result<(), AgentError> {
        crate::replay_metadata::safe_name(name)?;
        if !(2..=MAX_FILE_BYTES as usize).contains(&wire.len()) {
            return Err(AgentError::AuthorityRollback);
        }
        let path = self.child(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| AgentError::AuthorityRollback)?;
        file.write_all(wire)
            .and_then(|()| file.sync_all())
            .map_err(|_| AgentError::AuthorityRollback)?;
        self.exact_opened(&path, &file, wire.len() as u64)
    }
    pub fn replace(&self, name: &str, temporary: &str, wire: &[u8]) -> Result<(), AgentError> {
        self.create(temporary, wire)?;
        fs::rename(self.child(temporary), self.child(name))
            .map_err(|_| AgentError::AuthorityRollback)?;
        self.sync()
    }
    pub fn remove(&self, name: &str) -> Result<(), AgentError> {
        let _ = self.read(name)?;
        fs::remove_file(self.child(name)).map_err(|_| AgentError::AuthorityRollback)?;
        self.sync()
    }
    pub fn sync(&self) -> Result<(), AgentError> {
        self.file
            .sync_all()
            .map_err(|_| AgentError::AuthorityRollback)
    }
    fn exact_opened(&self, path: &Path, file: &File, length: u64) -> Result<(), AgentError> {
        let fd = file.metadata().map_err(|_| AgentError::AuthorityRollback)?;
        let named = fs::symlink_metadata(path).map_err(|_| AgentError::AuthorityRollback)?;
        valid_file(&fd, self.uid, false)?;
        (fd.len() == length && same(&fd, &named))
            .then_some(())
            .ok_or(AgentError::AuthorityRollback)
    }
}

pub(super) fn content_name(prefix: &str, revision: u64, wire: &[u8]) -> String {
    format!("{prefix}-{revision:020}-{}.json", digest_hex(wire))
}
