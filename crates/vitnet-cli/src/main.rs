use clap::Parser;
use std::io::{IsTerminal, Write};
use vitnet_cli::{Cli, Command, DgmlCommand, ModeArg, execute_with_index_control};
use vitnet_dgml::IndexControl;

#[cfg(windows)]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let cli = Cli::parse();
    let mut control = IndexControl::default();
    if !cli.quiet
        && (cli.progress == ModeArg::Always
            || (cli.progress == ModeArg::Auto && std::io::stderr().is_terminal()))
    {
        control.progress =
            Some(|phase, records| eprintln!("dgml.index: {phase} ({records} records)"));
    }
    let cancellation = control.clone();
    if matches!(&cli.command, Command::Dgml(arguments) if matches!(arguments.command, DgmlCommand::Index { .. }))
    {
        if let Err(error) = ctrlc::set_handler(move || cancellation.cancel()) {
            eprintln!("io.signal_handler: {error}");
            std::process::exit(vitnet_core::ExitCode::IoOrCache.as_i32());
        }
    }
    match execute_with_index_control(&cli, &control) {
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
