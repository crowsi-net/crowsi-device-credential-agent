use ihat_identity_assertion_contracts::{AuthorityCommand, AuthorityEvidence, command_digest};

use crate::{AgentError, source_approve_revocation_request as request};

use super::source_approve_revocation_test_values::{FixtureSigner, NOW, device, fresh, session};

#[test]
fn device_begin_prebuild_is_exact_and_closed() {
    let prepared = device("device-a");
    let fresh = fresh(&prepared);
    let value = request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("prebuild");
    request::validate_begin(&prepared, &fresh, &value, NOW).expect("exact request");
    let AuthorityCommand::BeginDeviceRevocation(command) = &value.command else {
        panic!("device command")
    };
    assert_eq!(command.finalize_command_id, prepared.operation_id);
    assert_eq!(command.source_device_id, prepared.source_device_ref);
    assert_eq!(command.source_session_ref, prepared.source_session_ref);
    assert_eq!(command.target_device_id, "device-a");
    assert!(matches!(
        value.evidence.as_slice(),
        [AuthorityEvidence::FreshUv(_), AuthorityEvidence::Signed(_)]
    ));

    let mut changed = value.clone();
    let AuthorityCommand::BeginDeviceRevocation(command) = &mut changed.command else {
        unreachable!()
    };
    command.service_id = "service-b".into();
    assert_eq!(
        request::validate_begin(&prepared, &fresh, &changed, NOW),
        Err(AgentError::RequestInvalid)
    );
}

#[test]
fn session_begin_binds_target_epoch_and_evidence_order() {
    let prepared = session("device-b");
    let fresh = fresh(&prepared);
    let value = request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("prebuild");
    let AuthorityCommand::BeginSessionRevocation(command) = &value.command else {
        panic!("session command")
    };
    assert_eq!(command.target_session_ref, "session-b");
    assert_eq!(command.expected_session_epoch, 5);

    let mut reordered = value.clone();
    reordered.evidence.reverse();
    assert_eq!(
        request::validate_begin(&prepared, &fresh, &reordered, NOW),
        Err(AgentError::RequestInvalid)
    );
}

#[test]
fn begin_rejects_cross_kind_proof_identifier_reuse() {
    let prepared = device("device-a");
    let fresh = fresh(&prepared);
    let mut value = request::begin(&FixtureSigner, &prepared, &fresh, NOW).expect("prebuild");
    let AuthorityCommand::BeginDeviceRevocation(command) = &mut value.command else {
        unreachable!()
    };
    command.sender_proof_id = fresh.proof_id.clone();
    let binding = command_digest(&value).expect("binding");
    let AuthorityEvidence::Signed(sender) = &mut value.evidence[1] else {
        unreachable!()
    };
    sender.proof_id = fresh.proof_id.clone();
    sender.binding_sha256 = binding;
    assert_eq!(
        request::validate_begin(&prepared, &fresh, &value, NOW),
        Err(AgentError::RequestInvalid)
    );
}
