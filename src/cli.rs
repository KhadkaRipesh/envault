use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "envault", about = "Local-first encrypted secrets manager")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scaffold envault.toml and .envault/secrets.enc, set master password.
    Init {
        /// Do not gitignore .envault/secrets.enc (opt to commit it).
        #[arg(long)]
        shared: bool,
    },
    /// Prompt for a secret value and encrypt it into the store for a profile/key.
    Set {
        /// Profile name (e.g. dev, prod)
        profile: String,
        /// Secret key name (e.g. DATABASE_URL)
        key: String,
    },
    /// List key names for a profile (values masked).
    List {
        /// Profile name
        profile: String,
    },
    /// Decrypt profile secrets and run a command with them in the environment.
    Run {
        /// Profile name
        #[arg(long)]
        profile: String,
        /// Command and arguments to execute
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Import all entries from a .env file into a profile, then delete the file.
    Import {
        /// Path to the .env file
        path: String,
        /// Profile name
        #[arg(long)]
        profile: String,
    },
}
