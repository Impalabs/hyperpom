use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use eyre::Result;
use hyperpom as hp;
use hyperpom::applevisor as av;
use hyperpom::config::*;
use hyperpom::core::*;
use hyperpom::corpus::*;
use hyperpom::crash::*;
use hyperpom::hooks::*;

use crate::loader::*;

/// The configuration object created from the CLI arguments passed to upngzz.
#[derive(Parser, Debug)]
#[clap(
    author = "lyte <hyperpom@impalabs.com>",
    version = "1.0",
    about = "upng fuzzer",
    long_about = None)]
pub struct Config {
    /// Subcommands.
    #[clap(subcommand)]
    command: Commands,
}

/// Fuzzer's CLI subcommands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Fuzzing subcommand.
    #[clap(arg_required_else_help = true)]
    Fuzz(FuzzSubCommand),

    /// Tracing subcommand.
    #[clap(arg_required_else_help = true)]
    Trace(TraceSubCommand),
}

#[derive(Debug, Args)]
pub struct FuzzSubCommand {
    /// Path to the binary to fuzz.
    #[clap(short = 'b', long = "binary", value_name = "BINARY", required = true,
        value_hint = clap::ValueHint::FilePath)]
    binary: PathBuf,

    /// Path to the directory containing the shared libraries.
    #[clap(short = 'l', long = "libs", value_name = "LIBS",
        value_hint = clap::ValueHint::DirPath)]
    libs: Option<PathBuf>,

    /// Path to the corpus.
    #[clap(short = 'c', long = "corpus", value_name = "CORPUS", required = true,
        value_hint = clap::ValueHint::DirPath)]
    corpus_dir: PathBuf,

    /// Path to the work directory.
    #[clap(short = 'd', long = "workdir", value_name = "WORKDIR", required = true,
        value_hint = clap::ValueHint::DirPath)]
    work_dir: PathBuf,

    /// Number of workers to spawn.
    #[clap(
        short = 'w',
        long = "workers",
        value_name = "WORKERS",
        default_value = "1"
    )]
    nb_workers: u32,

    /// Number of testcases executed by the worker before stopping.
    #[clap(short = 'i', long = "iterations", value_name = "ITERATIONS")]
    nb_iterations: Option<u64>,

    /// Physical address space size available to the fuzzer.
    #[clap(short = 's', long = "size", value_name = "SIZE", required = true,
        parse(from_str = from_hex))]
    as_size: usize,
}

#[derive(Debug, Args)]
pub struct TraceSubCommand {
    /// Path to the binary to fuzz.
    #[clap(short = 'b', long = "binary", value_name = "BINARY", required = true,
        value_hint = clap::ValueHint::FilePath)]
    binary: PathBuf,

    /// Path to the directory containing the shared libraries.
    #[clap(short = 'l', long = "libs", value_name = "LIBS",
        value_hint = clap::ValueHint::DirPath)]
    libs: Option<PathBuf>,

    /// Path to the testcase to trace.
    #[clap(short = 't', long = "testcase", value_name = "TESTCASE", required = true,
        value_hint = clap::ValueHint::FilePath)]
    testcase: PathBuf,

    /// Path to the trace output file.
    #[clap(short = 'o', long = "trace", value_name = "TRACE", required = true,
        value_hint = clap::ValueHint::FilePath)]
    trace: PathBuf,

    /// Physical address space size available to the fuzzer.
    #[clap(short = 's', long = "size", value_name = "SIZE", required = true,
        parse(from_str = from_hex))]
    as_size: usize,
}

pub fn from_hex(hex: &str) -> usize {
    let hex_stripped = hex.trim_start_matches("0x");
    usize::from_str_radix(hex_stripped, 16).expect("could not parse hex number")
}

pub fn entry(config: Config) -> Result<()> {
    match config.command {
        Commands::Fuzz(sub) => fuzz(sub),
        Commands::Trace(sub) => trace(sub),
    }
}

pub fn fuzz(config: FuzzSubCommand) -> Result<()> {
    // Instanciates global and local data.
    let gdata = GlobalData::new(None::<&std::path::Path>);
    let ldata = LocalData::new();
    // Creates a loader for the target binary.
    let loader = PngLoader::new(config.binary)?;
    // Creates a config for the fuzzer.
    let config = FuzzConfig::<LocalData, GlobalData>::builder(
        config.as_size,
        config.work_dir,
        config.corpus_dir,
    )
    .nb_workers(config.nb_workers)
    .seed(0xdeadbeefdeadbeef)
    .max_nb_mutations(0x800)
    .max_testcase_size(PngLoader::TESTCASE_MAX_SIZE)
    .timeout(Duration::new(60, 0))
    .iterations(config.nb_iterations)
    .build();
    // Creates an instance of the fuzzer.
    let mut hp =
        HyperPom::<_, _, _>::new(config, loader, ldata, gdata).expect("could not create fuzzer");
    // Start fuzzing!
    hp.fuzz()?;
    Ok(())
}

pub fn trace(config: TraceSubCommand) -> Result<()> {
    let _vm = av::VirtualMachine::new();
    // Instanciates global and local data.
    let gdata = GlobalData::new(Some(&config.trace));
    let ldata = LocalData::new();
    // Reads the testcase from disk.
    let testcase = Testcase::from_file(config.testcase)?;
    // Creates a loader for the target binary.
    let loader = PngLoader::new(config.binary)?;
    // Creates a config for the fuzzer.
    let config = ExecConfig::<LocalData, GlobalData>::builder(config.as_size)
        .nb_workers(1)
        .timeout(Duration::new(60, 0))
        .iterations(Some(1))
        .tracer(true)
        .tracer_hook(tracer_hook)
        .build();
    // Creates an instance of the fuzzer.
    let mut executor =
        Executor::<PngLoader, LocalData, GlobalData>::new(config, loader, ldata, gdata)
            .expect("could not create the executor");
    // Start tracing!
    executor.init()?;
    executor.run(Some(&testcase)).expect("execution failed");
    println!("{}", executor.vcpu);
    println!("Testcase covered {:?} paths", executor.cdata.set.len());
    Ok(())
}

/// Handles tracing hooks and displays the current instruction to `stdout`.
pub fn tracer_hook(args: &mut HookArgs<LocalData, GlobalData>) -> hp::error::Result<ExitKind> {
    let gd = args.gdata.write().unwrap();
    let mut trace = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&gd.path.as_ref().unwrap())
        .unwrap();
    CSE.with(|cs| {
        let insns = cs
            .disasm_count(args.insn, args.addr, 1)
            .expect("could not disassemble while adding coverage hooks");
        let insn = insns.as_ref().get(0).unwrap();
        writeln!(trace, "{}", insn).expect("could append instructions to the trace");
    });
    Ok(ExitKind::Continue)
}
