use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::{AgentError, test_support::AgentCore};

use crate::{
    management_support::{Fixture, NOW},
    management_support_identity::FakeIdentity,
    management_support_request,
    management_support_transport::FakeTransport,
    source_approve_support as approve, source_self_revocation_support as support,
};

type Core = AgentCore<FakeTransport, FakeIdentity>;

#[test]
fn signed_preaccept_failure_and_browser_substitution_never_invoke_final() {
    on_integration_stack(|| {
        for kind in [support::Kind::Device, support::Kind::Session] {
            preaccept_gate(kind);
        }
    });
}

#[test]
fn signed_preaccept_is_durable_before_final_can_be_retried() {
    on_integration_stack(|| {
        for kind in [support::Kind::Device, support::Kind::Session] {
            durable_preaccept_before_final(kind);
        }
    });
}

#[test]
fn final_transport_loss_restarts_after_expiry_and_identity_trust_rotation_exactly() {
    on_integration_stack(|| {
        for kind in [support::Kind::Device, support::Kind::Session] {
            recover_after_final(kind, support::FinalOutcome::Unknown);
            recover_after_final(kind, support::FinalOutcome::Completed);
        }
    });
}

#[test]
fn finalize_bindings_and_signed_final_exchange_substitution_fail_closed() {
    on_integration_stack(|| {
        for kind in [support::Kind::Device, support::Kind::Session] {
            substituted_final_exchange(kind);
            for case in 0..6 {
                substituted_finalize_projection(kind, case);
            }
        }
    });
}

fn on_integration_stack(run: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name("self-revocation-production-path".into())
        .stack_size(4 * 1024 * 1024)
        .spawn(run)
        .expect("spawn self revocation integration")
        .join()
        .expect("self revocation integration");
}

include!("source_self_revocation_test_setup.rs");
include!("source_self_revocation_test_binding.rs");
include!("source_self_revocation_test_gate.rs");
include!("source_self_revocation_test_recovery.rs");
include!("source_self_revocation_test_substitution.rs");
