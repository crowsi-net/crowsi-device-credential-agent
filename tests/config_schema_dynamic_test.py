import copy
import unittest

from jsonschema import Draft202012Validator

from config_schema_fixture import load_schema, valid_config


class ConfigSchemaDynamicTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = Draft202012Validator(load_schema())

    def assert_rejected(self, document):
        self.assertTrue(list(self.validator.iter_errors(document)))

    def test_current_complete_document_is_accepted(self):
        self.validator.validate(valid_config())

    def test_every_rust_mapping_field_is_required(self):
        original = valid_config()
        containers = [
            (),
            ("authority_route",),
            ("identity_authority_route",),
            ("pa_authorization_route",),
            ("management_projection_trust",),
            ("owner_mappings", 0),
            ("device_proof_keys", 0),
        ]
        for path in containers:
            source = self.at(original, path)
            for field in source:
                with self.subTest(path=path, field=field):
                    candidate = copy.deepcopy(original)
                    del self.at(candidate, path)[field]
                    self.assert_rejected(candidate)

    def test_unknown_fields_are_rejected_at_every_level(self):
        for path in [
            (), ("authority_route",), ("identity_authority_route",),
            ("pa_authorization_route",), ("management_projection_trust",),
            ("owner_mappings", 0), ("device_proof_keys", 0),
        ]:
            with self.subTest(path=path):
                candidate = valid_config()
                self.at(candidate, path)["unexpected"] = True
                self.assert_rejected(candidate)

    def test_old_versions_and_local_authority_fields_are_rejected(self):
        for version in ("v1", "v2", "v3", "v4"):
            candidate = valid_config()
            candidate["schema"] = f"crowsi://device-credential-agent/config/{version}"
            self.assert_rejected(candidate)
        for field in (
            "authority_executable", "authority_executable_sha256",
            "authority_config", "authority_config_path", "authority_command",
            "authority_arguments", "local_authority_subprocess",
        ):
            with self.subTest(field=field):
                candidate = valid_config()
                candidate[field] = "/legacy/forbidden"
                self.assert_rejected(candidate)

    def test_identity_generation_and_authority_policy_are_closed(self):
        for field, value in (
            ("minimum_identity_config_generation", 0),
            ("identity_finalization_authority_id", ""),
            ("revocation_approval_authority_ref", "x" * 129),
            ("revocation_approval_authority_ref", " authority-c"),
        ):
            with self.subTest(field=field):
                candidate = valid_config()
                candidate[field] = value
            self.assert_rejected(candidate)

    def test_user_verification_credential_is_root_signed_and_base64url(self):
        for value in ("", "credential with spaces", "credential=padding", "x" * 129):
            with self.subTest(value=value):
                candidate = valid_config()
                candidate["user_verification_credential_id"] = value
                self.assert_rejected(candidate)
        for value in ("", "a" * 63, "A" * 64, "g" * 64):
            with self.subTest(account_binding=value):
                candidate = valid_config()
                candidate["user_verification_account_binding_sha256"] = value
                self.assert_rejected(candidate)

    def test_endpoint_state_binding_is_closed(self):
        for field, value in (
            ("endpoint_deployment_id", ""),
            ("configuration_generation", 0),
            ("endpoint_state_directory", "relative/state"),
            ("endpoint_anchor_directory", "relative/anchor"),
        ):
            with self.subTest(field=field):
                candidate = valid_config()
                candidate[field] = value
                self.assert_rejected(candidate)

    @staticmethod
    def at(document, path):
        value = document
        for part in path:
            value = value[part]
        return value


if __name__ == "__main__":
    unittest.main()
