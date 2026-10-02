# crowsi-device-credential-agent

Connect a managed device to the credential authority through the declared management contract.

## What you can do

- Validate device-management requests.
- Translate admitted requests into strict authority envelopes.

## Current scope

Device registration, trust and deployment-specific transport are prerequisites supplied by the operator.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Detailed documentation](docs) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
