mod cli;
mod crypto;
mod store;
mod commands;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use commands::{import, init, list, run, set};
use cli::Commands;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { shared } => init::execute(shared),
        Commands::Set { profile, key } => set::execute(profile, key),
        Commands::List { profile } => list::execute(profile),
        Commands::Run { profile, command } => run::execute(profile, command),
        Commands::Import { path, profile } => import::execute(path, profile),
    }
}
