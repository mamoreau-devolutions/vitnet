use clap::Parser;
use std::io::Write;
use vitnet_cli::{Cli, execute};

fn main() {
    let cli = Cli::parse();
    match execute(&cli) {
        Ok(output) => {
            if let Some(path) = &cli.output {
                if let Err(error) = std::fs::write(path, output) {
                    eprintln!("{}: {error}", path.display());
                    std::process::exit(vitnet_core::ExitCode::IoOrCache.as_i32());
                }
            } else {
                let mut stdout = std::io::stdout().lock();
                if let Err(error) = writeln!(stdout, "{output}") {
                    eprintln!("stdout: {error}");
                    std::process::exit(vitnet_core::ExitCode::IoOrCache.as_i32());
                }
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(error.exit_code().as_i32());
        }
    }
}
