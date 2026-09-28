mod cli;
mod collector;
mod cpu;
mod daemon;
mod diagnose;
mod io;
mod memory;
mod network;
mod offcpu;
mod output;
mod process;
mod runtime;
mod stats;
mod symbolize;

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
        Command::Cpu(args) => cpu::run(args),
        Command::Io(args) => io::run(args),
        Command::Net(args) => network::run(args),
        Command::OffCpu(args) => offcpu::run(args),
        Command::Memory(args) => memory::run(args),
        Command::Diagnose(args) => diagnose::run(args),
        Command::Daemon(args) => {
            daemon::run_daemon(args.pid, args.duration, args.trigger, args.output)
        }
    }
}
