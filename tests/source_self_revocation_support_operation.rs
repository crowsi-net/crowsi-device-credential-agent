pub fn operation(
    kind: Kind,
    prepared: &EndpointPreparedOperationV2,
    begin: &SignedAuthorityExchangeV1,
) -> ManagementOperationV2 {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        panic!("fresh UV options")
    };
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: operation_kind(kind),
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingSourceUv,
        state_revision: 1,
        created_at_epoch_s: NOW,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: prepared.source_device_ref.clone(),
        scope: scope(kind),
        actor: ActorRequirementV2 {
            role: RequiredActorRole::SourceDevice,
            required_actor_device_ref: Some(prepared.source_device_ref.clone()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        },
        webauthn_options: Some(WebAuthnOptionsV2 {
            attempt_id: options.attempt_id.clone(),
            challenge: options.challenge.clone(),
            rp_id: options.rp_id.clone(),
            origin: options.origin.clone(),
            credential_id: options.credential_id.clone(),
            timeout_ms: options.timeout_ms,
            expires_at_epoch_s: options.expires_at_epoch_s,
            command_binding_sha256: options.command_binding_sha256.clone(),
        }),
        reason: None,
        reconcile_digest: None,
    }
}

pub fn preaccepted(
    kind: Kind,
    prepared: &EndpointPreparedOperationV2,
    begin: &SignedAuthorityExchangeV1,
) -> ManagementOperationV2 {
    let mut value = operation(kind, prepared, begin);
    value.state = ManagementOperationState::AwaitingRevocationFinal;
    value.state_revision = 2;
    value.actor = reconcile_actor();
    value.webauthn_options = None;
    value.reconcile_digest = Some("44".repeat(32));
    value
}

fn operation_kind(kind: Kind) -> ManagementOperationKind {
    match kind {
        Kind::Device => ManagementOperationKind::DeviceRevocation,
        Kind::Session => ManagementOperationKind::SessionRevocation,
    }
}

fn scope(kind: Kind) -> ManagementOperationScopeV2 {
    match kind {
        Kind::Device => ManagementOperationScopeV2::DeviceRevocation {
            target_device_ref: "device-a".into(),
            expected_device_revocation_epoch: 1,
            revokes_session_refs: vec![SESSION.into()],
            rotates_credential_refs: vec!["credential-a".into()],
            preserves_device_refs: vec!["device-b".into()],
        },
        Kind::Session => ManagementOperationScopeV2::SessionRevocation {
            target_session_ref: SESSION.into(),
            expected_session_revocation_epoch: 1,
            device_ref: "device-a".into(),
        },
    }
}

fn reconcile_actor() -> ActorRequirementV2 {
    ActorRequirementV2 {
        role: RequiredActorRole::ReconcileOnly,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    }
}
