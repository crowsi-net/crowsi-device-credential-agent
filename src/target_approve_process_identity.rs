use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata, OpenOptions},
    io::Read,
    os::fd::{AsRawFd, RawFd},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use crate::AgentError;

const MAXIMUM_EXECUTABLE_BYTES: u64 = 67_108_864;

pub(super) struct ProcessIdentity {
    file: File,
    metadata: StableMetadata,
}

impl ProcessIdentity {
    pub(super) fn open(path: &str, digest: &str) -> Result<Self, AgentError> {
        let path = Path::new(path);
        if !path.is_absolute() || !crate::validation::digest(digest) {
            return Err(AgentError::ConfigInvalid);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| AgentError::AuthorityUnavailable)?;
        let before = file
            .metadata()
            .map_err(|_| AgentError::AuthorityUnavailable)?;
        let uid = crate::process_identity::effective_uid()?;
        if !valid(&before, uid) {
            return Err(AgentError::ConfigInvalid);
        }
        let expected = StableMetadata::from(&before);
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAXIMUM_EXECUTABLE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AgentError::AuthorityUnavailable)?;
        let after = file
            .metadata()
            .map_err(|_| AgentError::AuthorityUnavailable)?;
        let exact = bytes.len() <= MAXIMUM_EXECUTABLE_BYTES as usize
            && StableMetadata::from(&after) == expected
            && format!("sha256:{:x}", Sha256::digest(&bytes)) == digest;
        if !exact {
            return Err(AgentError::ConfigInvalid);
        }
        fcntl(file.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty()))
            .map_err(|_| AgentError::AuthorityUnavailable)?;
        Ok(Self {
            file,
            metadata: expected,
        })
    }

    pub(super) fn path(&self) -> Result<String, AgentError> {
        let current = self
            .file
            .metadata()
            .map_err(|_| AgentError::AuthorityUnavailable)?;
        let uid = crate::process_identity::effective_uid()?;
        (StableMetadata::from(&current) == self.metadata && valid(&current, uid))
            .then(|| format!("/proc/self/fd/{}", self.fd()))
            .ok_or(AgentError::AuthorityUnavailable)
    }

    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct StableMetadata {
    device: u64,
    inode: u64,
    length: u64,
    links: u64,
    uid: u32,
    mode: u32,
    modified_s: i64,
    modified_ns: i64,
}

impl From<&Metadata> for StableMetadata {
    fn from(value: &Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            length: value.len(),
            links: value.nlink(),
            uid: value.uid(),
            mode: value.mode(),
            modified_s: value.mtime(),
            modified_ns: value.mtime_nsec(),
        }
    }
}

fn valid(value: &Metadata, uid: u32) -> bool {
    value.is_file()
        && value.nlink() == 1
        && (value.uid() == 0 || value.uid() == uid)
        && value.len() > 0
        && value.len() <= MAXIMUM_EXECUTABLE_BYTES
        && value.mode() & 0o111 != 0
        && value.mode() & 0o022 == 0
}
