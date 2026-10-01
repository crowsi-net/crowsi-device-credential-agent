impl Fixture {
    pub fn respond_lookup(
        &self,
        mut value: EndpointPreparedLookupResponseV1,
        change: impl FnOnce(&mut EndpointPreparedLookupResponseV1),
    ) -> EndpointPreparedLookupResponseV1 {
        change(&mut value);
        value.signature = hex::encode(
            self.projection_key
                .sign(
                    &canonical_endpoint_prepared_lookup_response(&value)
                        .expect("canonical lookup response"),
                )
                .to_bytes(),
        );
        self.transport
            .respond_lookup(serde_json::to_vec(&value).expect("lookup response"));
        value
    }

    pub fn revocation_begin_requests(
        &self,
    ) -> Vec<ihat_identity_assertion_contracts::AuthorityRequestV1> {
        self.identity.revocation_begin_requests()
    }

    pub fn fail_revocation_begin_once(&self) {
        self.identity.fail_revocation_begin_once();
    }

    pub fn revocation_final_requests(
        &self,
    ) -> Vec<ihat_identity_assertion_contracts::AuthorityRequestV1> {
        self.identity.revocation_final_requests()
    }

    pub fn substitute_revocation_final_once(&self) {
        self.identity.substitute_revocation_final_once();
    }

    pub fn fail_revocation_final_once(&self) {
        self.identity.fail_revocation_final_once();
    }

    pub fn finalize_requests(&self) -> Vec<Vec<u8>> {
        self.transport.finalize_requests()
    }

    pub fn source_approve_requests(&self) -> Vec<Vec<u8>> {
        self.transport.source_approve_requests()
    }

    pub fn reservation_requests(&self) -> Vec<Vec<u8>> {
        self.transport.reservation_requests()
    }

    pub fn fail_finalize_once(&self) {
        self.transport.fail_finalize_once();
    }

    pub fn fail_source_approve_once(&self) {
        self.transport.fail_source_approve_once();
    }

    pub fn respond_finalize(
        &self,
        mut value: ManagementProjectionV2,
        change: impl FnOnce(&mut ManagementProjectionV2),
    ) -> ManagementProjectionV2 {
        change(&mut value);
        value.signature = hex::encode(
            self.projection_key
                .sign(&canonical_management_projection(&value).expect("canonical projection"))
                .to_bytes(),
        );
        self.transport
            .respond_finalize(serde_json::to_vec(&value).expect("finalize response"));
        value
    }

    pub fn rotated_identity_core(&self, now: u64) -> AgentCore<FakeTransport, FakeIdentity> {
        let mut config: Value = serde_json::from_slice(&self.config).expect("config");
        config["configuration_generation"] = 2.into();
        config["minimum_identity_config_generation"] = 2.into();
        config["authority_response_key_id"] = "rotated-authority-response-key".into();
        config["authority_response_public_key_hex"] =
            hex::encode(SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes()).into();
        sign_config(&mut config, &SigningKey::from_bytes(&[1; 32]));
        AgentCore::from_documents(
            &serde_json::to_vec(&config).expect("rotated config"),
            &self.trust,
            self.transport.clone(),
            self.identity.clone(),
            now,
        )
        .expect("rotated core")
    }

    pub fn raised_identity_generation_core(
        &self,
        now: u64,
    ) -> AgentCore<FakeTransport, FakeIdentity> {
        let mut config: Value = serde_json::from_slice(&self.config).expect("config");
        config["configuration_generation"] = 2.into();
        config["minimum_identity_config_generation"] = 2.into();
        sign_config(&mut config, &SigningKey::from_bytes(&[1; 32]));
        AgentCore::from_documents(
            &serde_json::to_vec(&config).expect("raised config"),
            &self.trust,
            self.transport.clone(),
            self.identity.clone(),
            now,
        )
        .expect("raised generation core")
    }
}
