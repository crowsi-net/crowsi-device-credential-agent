fn awaiting_approval(prepared: &EndpointPreparedOperationV2) -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: ManagementOperationKind::DeviceRevocation,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingIndependentApproval,
        state_revision: 3,
        created_at_epoch_s: NOW - 1,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: "device-b".into(),
        scope: ManagementOperationScopeV2::DeviceRevocation {
            target_device_ref: "device-c".into(),
            expected_device_revocation_epoch: 1,
            revokes_session_refs: vec!["session-c-1".into(), "session-c-2".into()],
            rotates_credential_refs: vec!["credential-c".into()],
            preserves_device_refs: vec!["device-a".into(), "device-b".into()],
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::IndependentApproval,
            required_actor_device_ref: None,
            required_approval_authority_ref: Some("independent-authority-c".into()),
            excluded_actor_device_refs: vec!["device-b".into(), "device-c".into()],
        },
        webauthn_options: None,
        reason: None,
        reconcile_digest: None,
    }
}
