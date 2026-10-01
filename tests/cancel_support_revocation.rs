pub fn revocation_prepared(expires: u64) -> EndpointPreparedOperationV2 {
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "af".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: SESSION.into(),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "psa_owner_0000000000000001".into(),
        source_identity_nonce: "self-revocation-source-nonce".into(),
        nonce: "cancel-self-revocation-nonce".into(),
        issued_at_epoch_s: NOW - 301,
        expires_at_epoch_s: expires,
        intent: ManagementIntentV2::DeviceRevocation {
            service_id: "service-a".into(),
            target_device_ref: "device-a".into(),
            expected_device_revocation_epoch: 1,
            expected_snapshot_revision: 1,
            nonce: "self-revocation-intent-nonce".into(),
        },
        revocation: Some(RevocationRequirementsV2 {
            target_device_ref: "device-a".into(),
            required_approval_authority_ref: None,
            finalization_authority_id: "identity-authority".into(),
            expected_revoked_session_count: Some(1),
        }),
    };
    value.operation_id = endpoint_operation_id(&value).expect("revocation operation id");
    value
}

pub fn awaiting_final(prepared: &EndpointPreparedOperationV2) -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: ManagementOperationKind::DeviceRevocation,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingRevocationFinal,
        state_revision: 2,
        created_at_epoch_s: prepared.issued_at_epoch_s,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: "device-a".into(),
        scope: ManagementOperationScopeV2::DeviceRevocation {
            target_device_ref: "device-a".into(),
            expected_device_revocation_epoch: 1,
            revokes_session_refs: vec![SESSION.into()],
            rotates_credential_refs: vec!["credential-a".into()],
            preserves_device_refs: vec!["device-b".into()],
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::ReconcileOnly,
            required_actor_device_ref: None,
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        },
        webauthn_options: None,
        reason: None,
        reconcile_digest: Some("44".repeat(32)),
    }
}
