use crowsi_credential_authority_contracts::{
    MANAGEMENT_REQUEST_SCHEMA, ManagementCommandV2, ManagementRequestV2,
};

pub fn request(id: &str) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::Snapshot {
            service_id: "service-a".into(),
        },
    }
}
