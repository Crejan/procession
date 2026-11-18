//! `prover`: one command per question about a realtime host.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use p_rover::observe::{clock, cmdline, irq, nic, procs, sched, serial};
use p_rover::{Config, Env, Error, Report, render};
use p_roc::{CpuSet, Root};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
}

/// Diagnoses realtime behaviour of a Linux host. Exit codes: 0 nothing above
/// info, 1 warnings, 2 critical findings, 3 the diagnostic failed, 4 refused
/// (bad arguments or a limit).
#[derive(Parser)]
#[command(name = "prover", version)]
struct Cli {
    /// Output format.
    #[arg(long, value_enum, default_value = "text", global = true)]
    format: Format,
    /// Write the output to a file instead of stdout.
    #[arg(long, global = true)]
    output: Option<PathBuf>,
    /// Configuration file (default /etc/p-rover.toml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Read from a copy of the system's files instead: the /proc, /sys, /dev, /etc and /boot trees.
    #[command(flatten)]
    roots: Roots,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Args)]
struct Roots {
    /// Alternative /proc.
    #[arg(long, global = true, hide = true)]
    proc_root: Option<PathBuf>,
    /// Alternative /sys.
    #[arg(long, global = true, hide = true)]
    sys_root: Option<PathBuf>,
    /// Alternative /dev.
    #[arg(long, global = true, hide = true)]
    dev_root: Option<PathBuf>,
    /// Alternative /etc.
    #[arg(long, global = true, hide = true)]
    etc_root: Option<PathBuf>,
    /// Alternative /boot.
    #[arg(long, global = true, hide = true)]
    boot_root: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// RT threads and every thread on an isolated CPU (cost: light).
    Procs {
        /// At most this many thread records.
        #[arg(long, default_value_t = procs::DEFAULT_MAX)]
        max: usize,
    },
    /// Two samples of the RT threads and those on or allowed onto the chosen CPUs: run, wait and switch rates (cost: light).
    Sched {
        /// CPUs to watch (a list such as 2-3); default: the isolated set.
        #[arg(long)]
        cpus: Option<CpuSet>,
        /// Sampling window, 1s to 60s.
        #[arg(long, default_value = "5s", value_parser = humantime::parse_duration)]
        duration: Duration,
        /// At most this many thread records.
        #[arg(long, default_value_t = sched::DEFAULT_MAX)]
        max: usize,
    },
    /// Link, driver, counters, rings, coalescing, queues and their IRQs of one interface (cost: light; heavy with --delta).
    Nic {
        /// The interface.
        iface: String,
        /// Report only the counters that moved over this window (1s to 300s).
        #[arg(long, value_parser = humantime::parse_duration)]
        delta: Option<Duration>,
        /// List every counter, not only errors and drops.
        #[arg(long)]
        all_stats: bool,
    },
    /// Serial ports: the console, IRQ, counters, modem lines, getty (cost: light).
    Serial,
    /// Who disciplines CLOCK_REALTIME: chrony, ptp4l, phc2sys, PTP clocks (cost: light).
    Clock,
    /// Live kernel command line against the declared one, kernel flavour, sysctls (cost: light).
    Cmdline,
    /// IRQ affinity, /proc/interrupts delta, timer ticks (cost: light).
    Irq {
        /// Sampling window, 1s to 60s.
        #[arg(long, default_value = "5s", value_parser = humantime::parse_duration)]
        duration: Duration,
        /// How many unflagged IRQs to show.
        #[arg(long, default_value_t = irq::DEFAULT_TOP)]
        top: usize,
    },
}

fn run(cli: &Cli) -> Result<Report, Error> {
    let mut env = Env::system(Config::load(cli.config.as_deref())?);
    let r = &cli.roots;
    let sys = Root::system();
    env.root = Root::new(
        r.proc_root.clone().unwrap_or(sys.proc),
        r.sys_root.clone().unwrap_or(sys.sys),
        r.dev_root.clone().unwrap_or(sys.dev),
    );
    if let Some(p) = &r.etc_root {
        env.etc = p.clone();
    }
    if let Some(p) = &r.boot_root {
        env.boot = p.clone();
    }
    match &cli.command {
        Cmd::Procs { max } => procs::run(&env, &procs::Args { max: *max }),
        Cmd::Sched { cpus, duration, max } => {
            sched::run(&env, &sched::Args { cpus: cpus.clone(), duration: *duration, max: *max })
        }
        Cmd::Nic { iface, delta, all_stats } => {
            nic::run(&env, &nic::Args { iface: iface.clone(), delta: *delta, all_stats: *all_stats })
        }
        Cmd::Serial => serial::run(&env),
        Cmd::Clock => clock::run(&env),
        Cmd::Cmdline => cmdline::run(&env),
        Cmd::Irq { duration, top } => irq::run(&env, &irq::Args { duration: *duration, top: *top }),
    }
}

fn emit(cli: &Cli, report: &Report) -> Result<(), Error> {
    let body = match cli.format {
        Format::Text => render::text(report),
        Format::Json => {
            let mut s = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
            s.push('\n');
            s
        }
    };
    match &cli.output {
        Some(p) => std::fs::write(p, body)?,
        None => std::io::stdout().write_all(body.as_bytes())?,
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let help = !e.use_stderr();
            let _ = e.print();
            return ExitCode::from(if help { 0 } else { 4 });
        }
    };
    match run(&cli).and_then(|r| emit(&cli, &r).map(|()| r.exit_code())) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("prover: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}
