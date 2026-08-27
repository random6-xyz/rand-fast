mod cli;
mod collector;
mod output;
mod process;
mod stats;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Sched(args) => collector::run(args),
    }
}
