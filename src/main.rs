use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = std::env::args().collect::<Vec<_>>();
    match crowsi_device_credential_agent::run_cli(
        &arguments,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crowsi-device-credential-agent: {}", error.reason_code());
            ExitCode::FAILURE
        }
    }
}
