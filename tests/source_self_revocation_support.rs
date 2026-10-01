use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::management_support::{NOW, SESSION};

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Device,
    Session,
}

impl Kind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Session => "session",
        }
    }
}

pub fn request(kind: Kind, id: &str) -> ManagementRequestV2 {
    let intent = match kind {
        Kind::Device => ManagementIntentV2::DeviceRevocation {
            service_id: "service-a".into(),
            target_device_ref: "device-a".into(),
            expected_device_revocation_epoch: 1,
            expected_snapshot_revision: 1,
            nonce: "self-device-revocation-nonce".into(),
        },
        Kind::Session => ManagementIntentV2::SessionRevocation {
            service_id: "service-a".into(),
            target_session_ref: SESSION.into(),
            expected_session_revocation_epoch: 1,
            expected_snapshot_revision: 1,
            nonce: "self-session-revocation-nonce".into(),
        },
    };
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::SourceOptions { intent },
    }
}

pub fn snapshot() -> ManagementSnapshotV2 {
    crate::source_options_support::snapshot()
}

pub fn source_evidence(wire: &[u8]) -> (EndpointPreparedOperationV2, SignedAuthorityExchangeV1) {
    crate::source_options_support::source_evidence(wire)
}

include!("source_self_revocation_support_operation.rs");
include!("source_self_revocation_support_finalize.rs");
