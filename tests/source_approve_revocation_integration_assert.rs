fn assert_ceremony(wire: &[u8], stored: &ihat_identity_assertion_contracts::AuthorityRequestV1) {
    let envelope = decode_endpoint_management_envelope_strict(wire).expect("strict envelope");
    let EndpointManagementEvidenceV2::SourceApprove {
        revocation_ceremony: Some(ceremony),
        ..
    } = envelope.evidence
    else {
        panic!("source revocation ceremony")
    };
    assert_eq!(&ceremony.begin.request, stored);
    assert!(ceremony.final_revoke.is_none());
    let [
        AuthorityEvidence::FreshUv(fresh),
        AuthorityEvidence::Signed(sender),
    ] = ceremony.begin.request.evidence.as_slice()
    else {
        panic!("fresh UV and sender proof")
    };
    assert_eq!(sender.role, VerificationRole::SessionSender);
    assert_ne!(fresh.proof_id, sender.proof_id);
    assert_ne!(fresh.key_id, sender.key_id);
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(metadata),
    } = &ceremony.begin.response.outcome
    else {
        panic!("revocation begun")
    };
    assert!(metadata.independent_approval_required);
    let key = SigningKey::from_bytes(&[3; 32]);
    verify_authority_exchange_at(
        &ceremony.begin,
        "begin_device_revocation",
        1,
        "authority-response-key",
        &hex::encode(key.verifying_key().to_bytes()),
        NOW,
    )
    .expect("signed revocation begin");
}
