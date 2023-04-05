use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
/// The structure "clap" will parse
pub struct Cli {
    /// Path to dnslrd.conf is required
    #[arg(required = true)]
    pub path_to_confile: PathBuf,

    /// Command to process
    #[command(subcommand)]
    #[arg()]
    pub command: Commands
}

#[derive(Subcommand)]
/// The subcommands enum
pub enum Commands {
    /// Display the dnslrd configuration
    Showconf {},

    /// Add a new rule
    Set {
        matchclass: String,
        qtype: Option<String>,
        ip: Option<String>
    },

    /// Get info about a matchclass
    Get {matchclass: String},

    /// Delete a rule
    Delete {
        matchclass: String,
        qtype: Option<String>
    },

    /// Feed a list of domains to a matchclass
    Feed {
        path_to_list: PathBuf,
        matchclass: String
    },

    /// Dump a complete matchclass
    Dump {matchclass: String},

    /// Drop entries that match a matchclass pattern
    Drop {pattern: String},

    /// Get stats about IP addresses that match a prefix
    Stats {prefix: String},

    /// Clear stats about IP addresses that match a prefix
    Clear {prefix: String}
}