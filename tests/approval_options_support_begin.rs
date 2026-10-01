fn revocation_begin(prepared: &EndpointPreparedOperationV2) -> SignedAuthorityExchangeV1 {
    use ed25519_dalek::{Signer, SigningKey};
    use ihat_identity_assertion_contracts::{
        AuthenticatorKindDto, FRESH_UV_SCHEMA, FreshUvV1, canonical_fresh_uv,
    };

    let mut fresh = FreshUvV1 {
        schema: FRESH_UV_SCHEMA.into(),
        proof_id: "source-revocation-fresh".into(),
        credential_id: "webauthn-credential-b".into(),
        authenticator_key_fingerprint: "ab".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 14,
        challenge: "source-revocation-challenge".into(),
        attempt_id: "source-revocation-attempt".into(),
        identity_nonce: prepared.source_identity_nonce.clone(),
        source_device_id: prepared.source_device_ref.clone(),
        service_id: "service-a".into(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        session_ref: prepared.source_session_ref.clone(),
        operation_digest_sha256: endpoint_operation_digest(prepared).expect("operation digest"),
        subject_epoch: 1,
        service_epoch: 1,
        device_epoch: 1,
        session_epoch: 1,
        account_binding_sha256: "1a".repeat(32),
        key_id: "uv-key".into(),
        signature: String::new(),
    };
    fresh.signature = hex::encode(
        SigningKey::from_bytes(&[6; 32])
            .sign(&canonical_fresh_uv(&fresh).expect("canonical fresh"))
            .to_bytes(),
    );
    let request = crate::management_support_identity_revocation::prepare(prepared, &fresh, NOW)
        .expect("revocation request");
    crate::management_support_identity_revocation::exchange(prepared, &request, NOW)
        .expect("revocation begin")
}
