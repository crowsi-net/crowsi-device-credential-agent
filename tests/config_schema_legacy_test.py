import unittest

from config_schema_fixture import ROOT, ROOT_TRUST_PATH, SCHEMA_PATH


class ConfigSchemaLegacyRatchetTest(unittest.TestCase):
    DOCS = (ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "docs/provisioning.md")
    RETIRED = (
        "config/v1", "config/v2", "config/v3", "config/v4", "config/v5",
        "config-v1", "config-v2", "config-v3", "config-v4", "config-v5",
        "CROWSI-DEVICE-CREDENTIAL-CONFIG-V1",
        "CROWSI-DEVICE-CREDENTIAL-CONFIG-V2",
        "CROWSI-DEVICE-CREDENTIAL-CONFIG-V3",
        "CROWSI-DEVICE-CREDENTIAL-CONFIG-V4",
        "CROWSI-DEVICE-CREDENTIAL-CONFIG-V5",
        "authority_executable", "authority_config", "handle-once",
        "local authority connector", "executable authority connector",
    )

    def test_only_current_config_schema_is_distributed(self):
        schemas = sorted((ROOT / "schemas").glob("config-v*.schema.json"))
        self.assertEqual(schemas, [SCHEMA_PATH])

    def test_distribution_surface_has_zero_retired_config_terms(self):
        paths = (*self.DOCS, SCHEMA_PATH)
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for retired in self.RETIRED:
                with self.subTest(path=path, retired=retired):
                    self.assertNotIn(retired, text)

    def test_all_operator_docs_pin_v6_root_trust_and_remote_mtls(self):
        for path in self.DOCS:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path):
                self.assertIn("config-v6", text)
                self.assertIn(ROOT_TRUST_PATH, text)
                self.assertIn("remote mTLS only", text)
                self.assertNotIn(
                    "/etc/coela/device-credential-agent-root-trust.json", text
                )


if __name__ == "__main__":
    unittest.main()
