use std::process::ExitCode;

use clap::Parser;
use syscall_cli::cli::Cli;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    // Diagnostics go to stderr so stdout stays machine-readable.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match syscall_cli::execute(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("syscall: {err:#}");
            ExitCode::FAILURE
        }
    }
}
