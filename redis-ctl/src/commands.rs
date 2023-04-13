use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
/// The structure "clap" will parse
pub struct Cli {
    /// Path to dnsblrsd.conf is required
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
    Conf {},

    /// Get info about a matchclass
    Get {matchclass: String},

    /// Add a new rule
    Set {
        matchclass: String,
        qtype: Option<String>,
        ip: Option<String>
    },

    /// Delete a rule or a complete matchclass
    Del {
        matchclass: String,
        qtype: Option<String>
    },

    /// Drop all matchclasses that match a pattern
    Drop {pattern: String},

    /// Feed a list of domains to a matchclass
    Feed {
        path_to_list: PathBuf,
        matchclass: String
    },

    /// Display stats about IP addresses that match a pattern
    Stats {pattern: String},

    /// Clear stats about IP addresses that match a pattern
    Clear {pattern: String}
}