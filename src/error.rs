use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentError {
    AuthorityResponseInvalid,
    AuthorityRollback,
    AuthorityUnavailable,
    ConfigInvalid,
    CurrentStatusInvalid,
    FreshUserVerificationRequired,
    IdentityAssertionInvalid,
    IdentityUnavailable,
    OperationReplay,
    OwnerMappingUnknown,
    PathInvalid,
    RequestInvalid,
    ResponseInvalid,
    StatusNonceReplayed,
    TargetKeyProofInvalid,
}

impl AgentError {
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::AuthorityResponseInvalid => "device-credential-authority-response-invalid",
            Self::AuthorityRollback => "device-credential-authority-rollback-detected",
            Self::AuthorityUnavailable => "device-credential-authority-unavailable",
            Self::ConfigInvalid => "device-credential-config-invalid",
            Self::CurrentStatusInvalid => "device-credential-current-status-invalid",
            Self::FreshUserVerificationRequired => {
                "device-credential-fresh-user-verification-required"
            }
            Self::IdentityAssertionInvalid => "device-credential-identity-assertion-invalid",
            Self::IdentityUnavailable => "device-credential-identity-unavailable",
            Self::OperationReplay => "device-credential-operation-replayed",
            Self::OwnerMappingUnknown => "device-credential-owner-mapping-unknown",
            Self::PathInvalid => "device-credential-path-invalid",
            Self::RequestInvalid => "device-credential-request-invalid",
            Self::ResponseInvalid => "device-credential-response-invalid",
            Self::StatusNonceReplayed => "device-credential-status-nonce-replayed",
            Self::TargetKeyProofInvalid => "device-credential-target-key-proof-invalid",
        }
    }
}

impl Display for AgentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for AgentError {}
