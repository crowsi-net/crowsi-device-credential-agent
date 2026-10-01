use std::{fs::File, io::Read};

use crate::AgentError;

pub(crate) fn effective_uid() -> Result<u32, AgentError> {
    let file = File::open("/proc/self/status").map_err(|_| AgentError::PathInvalid)?;
    let mut wire = Vec::new();
    (&file)
        .take(8_193)
        .read_to_end(&mut wire)
        .map_err(|_| AgentError::PathInvalid)?;
    if wire.len() > 8_192 {
        return Err(AgentError::PathInvalid);
    }
    let status = std::str::from_utf8(&wire).map_err(|_| AgentError::PathInvalid)?;
    let mut lines = status.lines().filter(|line| line.starts_with("Uid:"));
    let line = lines.next().ok_or(AgentError::PathInvalid)?;
    if lines.next().is_some() {
        return Err(AgentError::PathInvalid);
    }
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    if fields.len() != 5 || fields[0] != "Uid:" {
        return Err(AgentError::PathInvalid);
    }
    fields[2].parse().map_err(|_| AgentError::PathInvalid)
}
