import re
import unittest

from config_schema_fixture import ROOT, SCHEMA_PATH, load_schema


class ConfigSchemaStaticTest(unittest.TestCase):
    def test_schema_is_valid_draft_2020_12(self):
        from jsonschema import Draft202012Validator

        schema = load_schema()
        Draft202012Validator.check_schema(schema)
        self.assertEqual(
            schema["$id"], "crowsi://device-credential-agent/config/v6"
        )

    def test_schema_fields_exactly_match_rust_documents(self):
        schema = load_schema()
        rust = (ROOT / "src/config.rs").read_text(encoding="utf-8")
        objects = {
            "AgentConfigDocument": schema,
            "RemoteAuthorityRoute": schema["$defs"]["remoteAuthorityRoute"],
            "PaAuthorizationRoute": schema["$defs"]["paAuthorizationRoute"],
            "ManagementProjectionTrust": schema["$defs"]["managementProjectionTrust"],
            "OwnerMapping": schema["$defs"]["ownerMapping"],
            "DeviceProofKeyTrust": schema["$defs"]["deviceProofKeyTrust"],
        }
        for name, contract in objects.items():
            with self.subTest(name=name):
                fields = self.rust_fields(rust, name)
                self.assertEqual(set(contract["properties"]), fields)
                self.assertEqual(set(contract["required"]), fields)
                self.assertIs(contract["additionalProperties"], False)

    @staticmethod
    def rust_fields(source, name):
        body = re.search(
            rf"pub struct {name}\s*\{{(?P<body>.*?)\n\}}", source, re.S
        )
        if body is None:
            raise AssertionError(f"missing Rust struct {name}")
        return set(re.findall(r"^\s*pub\s+(\w+):", body["body"], re.M))


if __name__ == "__main__":
    unittest.main()
