use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, EndpointPreparedOperationV2, ManagementCommandV2,
    ManagementProjectionBodyV2, ManagementRequestV2, SignedAuthorityExchangeV1,
    decode_endpoint_management_envelope_strict, verify_authority_exchange_at,
};
use crowsi_device_credential_agent::{AgentError, test_support::AgentCore};
use ed25519_dalek::SigningKey;
use ihat_identity_assertion_contracts::{
    AuthorityEvidence, AuthorityResult, ResponseOutcome, VerificationRole,
};

use crate::management_support_transport::FakeTransport;
use crate::{
    management_support::{Fixture, NOW},
    management_support_identity::FakeIdentity,
    management_support_request, source_approve_support as approve,
    source_options_support as source, source_revocation_support as revocation,
};

type Core = AgentCore<FakeTransport, FakeIdentity>;

struct SourceContext {
    core: Box<Core>,
    prepared: Box<EndpointPreparedOperationV2>,
    begin: Box<SignedAuthorityExchangeV1>,
}

#[test]
fn cross_device_revocation_retries_exact_begin_and_source_envelope() {
    std::thread::Builder::new()
        .name("cross-device-revocation-production-path".into())
        .stack_size(4 * 1024 * 1024)
        .spawn(run_cross_device_revocation)
        .expect("spawn revocation integration")
        .join()
        .expect("revocation integration");
}

fn run_cross_device_revocation() {
    let fixture = Fixture::new();
    let context = source_context(&fixture);
    approve_source(&fixture, &context);
}

include!("source_approve_revocation_integration_setup.rs");
include!("source_approve_revocation_integration_flow.rs");
include!("source_approve_revocation_integration_assert.rs");
