use crowsi_credential_authority_contracts::{
    ManagementProjectionV2, ManagementRequestV2,
    decode_endpoint_independent_revocation_finalize_request_strict,
};

use crate::{
    AgentError, VerifiedConfig, retired_request_types::RetiredRequestReceiptV1,
    transport::AuthorityTransport,
};

pub(super) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    transport: &T,
    browser: &ManagementRequestV2,
    value: &RetiredRequestReceiptV1,
    request_wire: &str,
    now: u64,
) -> Result<(Vec<u8>, ManagementProjectionV2), AgentError> {
    let request =
        decode_endpoint_independent_revocation_finalize_request_strict(request_wire.as_bytes())
            .map_err(|_| AgentError::AuthorityRollback)?;
    if value.route != "independent-revocation-finalize"
        || request.approve_revocation_request != *browser
        || request.operation_id != value.operation_id
    {
        return Err(AgentError::AuthorityRollback);
    }
    let wire = transport.exchange(
        "independent-revocation-finalize",
        request_wire.as_bytes(),
        now,
    )?;
    let projection =
        crate::independent_approve_finalize_flow::request_response(config, &request, &wire, now)?;
    exact_body(value, &projection)?;
    Ok((wire, projection))
}

fn exact_body(
    value: &RetiredRequestReceiptV1,
    projection: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    value
        .response
        .as_ref()
        .is_some_and(|expected| compatible(&expected.body, &projection.body))
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}

pub(super) fn compatible(
    old: &crowsi_credential_authority_contracts::ManagementProjectionBodyV2,
    new: &crowsi_credential_authority_contracts::ManagementProjectionBodyV2,
) -> bool {
    if old == new {
        return true;
    }
    matches!(
        (old, new),
        (
            crowsi_credential_authority_contracts::ManagementProjectionBodyV2::Operation {
                operation: prior,
            },
            crowsi_credential_authority_contracts::ManagementProjectionBodyV2::Operation {
                operation: next,
            },
        ) if prior.state
            == crowsi_credential_authority_contracts::ManagementOperationState::Unknown
            && next.state
                == crowsi_credential_authority_contracts::ManagementOperationState::Completed
            && prior.operation_id == next.operation_id
            && next.state_revision >= prior.state_revision
    )
}

#[cfg(test)]
mod tests {
    use crowsi_credential_authority_contracts::{
        ActorRequirementV2, ManagementOperationKind, ManagementOperationScopeV2,
        ManagementOperationState as State, ManagementOperationV2, ManagementProjectionBodyV2,
        ManagementReasonCode, RequiredActorRole,
    };

    #[test]
    fn finalize_receipt_advances_only_same_unknown_operation() {
        let old = body("operation", State::Unknown, 7);
        let completed = body("operation", State::Completed, 8);
        assert!(super::compatible(&old, &completed));
        assert!(!super::compatible(
            &completed,
            &body("operation", State::Unknown, 9)
        ));
        assert!(!super::compatible(
            &old,
            &body("substituted", State::Completed, 8)
        ));
    }

    fn body(id: &str, state: State, revision: u64) -> ManagementProjectionBodyV2 {
        ManagementProjectionBodyV2::Operation {
            operation: ManagementOperationV2 {
                operation_id: id.into(),
                kind: ManagementOperationKind::SessionRevocation,
                intent_digest_sha256: "a".repeat(64),
                state,
                state_revision: revision,
                created_at_epoch_s: 1,
                expires_at_epoch_s: 2,
                source_device_ref: "source".into(),
                scope: ManagementOperationScopeV2::SessionRevocation {
                    target_session_ref: "session".into(),
                    expected_session_revocation_epoch: 1,
                    device_ref: "device".into(),
                },
                actor: ActorRequirementV2 {
                    role: RequiredActorRole::ReconcileOnly,
                    required_actor_device_ref: None,
                    required_approval_authority_ref: None,
                    excluded_actor_device_refs: Vec::new(),
                },
                webauthn_options: None,
                reason: Some(ManagementReasonCode::OperationUnknown),
                reconcile_digest: Some("b".repeat(64)),
            },
        }
    }
}
