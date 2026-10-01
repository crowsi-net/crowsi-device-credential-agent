use serde::{Serialize, de::DeserializeOwned};

use crate::{AgentError, replay_file::PinnedDir, replay_record, replay_scan::Entry};

pub(super) const HISTORY: usize = 3;

pub(super) fn classify(names: &[String], state: bool) -> Result<(), AgentError> {
    for name in names {
        let known = name == "binding.json"
            || name == "sealed.json"
            || name == "committed.json"
            || name == "head.json"
            || (state && name == "ledger.lock")
            || (state && name == "execution.lock")
            || (state && parse_name(name, "state").is_some())
            || (!state && parse_name(name, "anchor").is_some());
        if !known {
            return Err(AgentError::AuthorityRollback);
        }
    }
    Ok(())
}

pub(super) fn entries<T: DeserializeOwned + Serialize>(
    dir: &PinnedDir,
    names: &[String],
    prefix: &str,
) -> Result<Vec<Entry<T>>, AgentError> {
    entries_limit(dir, names, prefix, HISTORY)
}

pub(super) fn entries_limit<T: DeserializeOwned + Serialize>(
    dir: &PinnedDir,
    names: &[String],
    prefix: &str,
    maximum: usize,
) -> Result<Vec<Entry<T>>, AgentError> {
    let mut result = Vec::new();
    for name in names {
        if let Some((revision, named_digest)) = parse_name(name, prefix) {
            let wire = dir.read(name)?;
            if replay_record::digest_hex(&wire) != named_digest {
                return Err(AgentError::AuthorityRollback);
            }
            result.push((
                revision,
                Entry {
                    name: name.clone(),
                    digest: replay_record::digest(&wire),
                    value: decode(&wire)?,
                },
            ));
        }
    }
    result.sort_by_key(|entry| entry.0);
    if result.len() > maximum {
        return Err(AgentError::AuthorityRollback);
    }
    Ok(result.into_iter().map(|entry| entry.1).collect())
}

pub(super) fn parse_name(name: &str, prefix: &str) -> Option<(u64, String)> {
    let body = name
        .strip_prefix(&format!("{prefix}-"))?
        .strip_suffix(".json")?;
    let (revision, digest) = body.split_once('-')?;
    if revision.len() != 20
        || digest.len() != 64
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some((revision.parse().ok()?, digest.to_owned()))
}

pub(super) fn decode<T: DeserializeOwned + Serialize>(wire: &[u8]) -> Result<T, AgentError> {
    let value: T = serde_json::from_slice(wire).map_err(|_| AgentError::AuthorityRollback)?;
    (crate::replay_record::wire(&value)? == wire)
        .then_some(value)
        .ok_or(AgentError::AuthorityRollback)
}
