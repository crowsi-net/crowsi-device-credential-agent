#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalOutcome {
    Unknown,
    Completed,
}

pub fn finalize_request(wire: &[u8]) -> EndpointRevocationFinalizeRequestV1 {
    decode_endpoint_revocation_finalize_request_strict(wire).expect("strict finalize request")
}

pub fn finalize_projection(
    request: &EndpointRevocationFinalizeRequestV1,
    preaccepted: &ManagementOperationV2,
    outcome: FinalOutcome,
    now: u64,
) -> ManagementProjectionV2 {
    let seed = crate::management_support_request::request("finalize-projection-seed");
    let mut value = crate::management_support_projection::projection(&seed, 4);
    value.projection_id = format!("finalize-projection-{now}");
    value
        .request_id
        .clone_from(&request.source_approve_request.request_id);
    value.command_digest_sha256 =
        management_command_digest(&request.source_approve_request).expect("source approve digest");
    let identity = identity_evidence_from_exchange(&request.accepted_identity_exchange)
        .expect("accepted identity");
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    value.service_id.clone_from(&assertion.service_id);
    value
        .pairwise_subject
        .clone_from(&assertion.pairwise_subject);
    value
        .opaque_account_ref
        .clone_from(&request.prepared.opaque_owner_ref);
    value.current_device_ref.clone_from(&assertion.device_id);
    value.current_session_ref.clone_from(&assertion.session_ref);
    value.subject_revocation_epoch = epochs.subject;
    value.service_revocation_epoch = epochs.service;
    value.device_revocation_epoch = epochs.device;
    value.session_revocation_epoch = epochs.session;
    value
        .device_posture_state
        .clone_from(&assertion.device_posture.state);
    value.device_posture_revision = assertion.device_posture.revision;
    value
        .device_proof_key_ref
        .clone_from(&assertion.device_proof_key_ref);
    value.snapshot_revision = match outcome {
        FinalOutcome::Unknown => 4,
        FinalOutcome::Completed => 5,
    };
    value.issued_at_epoch_s = now;
    value.expires_at_epoch_s = now + 30;
    value.body = ManagementProjectionBodyV2::Operation {
        operation: finalized_operation(request, preaccepted, outcome),
    };
    value.signature.clear();
    value
}

fn finalized_operation(
    request: &EndpointRevocationFinalizeRequestV1,
    preaccepted: &ManagementOperationV2,
    outcome: FinalOutcome,
) -> ManagementOperationV2 {
    let mut value = preaccepted.clone();
    value.state = match outcome {
        FinalOutcome::Unknown => ManagementOperationState::Unknown,
        FinalOutcome::Completed => ManagementOperationState::Completed,
    };
    value.state_revision = request.expected_state_revision
        + match outcome {
            FinalOutcome::Unknown => 1,
            FinalOutcome::Completed => 2,
        };
    value.actor = match outcome {
        FinalOutcome::Unknown => reconcile_actor(),
        FinalOutcome::Completed => ActorRequirementV2 {
            role: RequiredActorRole::NoActor,
            required_actor_device_ref: None,
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        },
    };
    value.reason = match outcome {
        FinalOutcome::Unknown => Some(ManagementReasonCode::ProviderOutcomeUnknown),
        FinalOutcome::Completed => None,
    };
    value.reconcile_digest = match outcome {
        FinalOutcome::Unknown => Some(request.reconcile_digest.clone()),
        FinalOutcome::Completed => None,
    };
    value
}
