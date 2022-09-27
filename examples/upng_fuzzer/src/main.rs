#![feature(array_zip)]

use clap::Parser;
use eyre::Result;

pub mod loader;
pub mod stubs;
pub mod upngzz;

fn main() -> Result<()> {
    // Creates a new configuration object that contains the arguments passed to the fuzzer.
    let config = upngzz::Config::parse();
    // Instanciates the fuzzer and starts fuzzing.
    upngzz::entry(config)?;
    Ok(())
}
