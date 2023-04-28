use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// The structure "clap" will parse
#[derive(Parser)]
#[command(about = "This is a command-line tool used to modify the Redis blacklist", long_about = None)]
pub struct Cli {
    /// Path to dnsblrsd.conf is required
    #[arg(required = true)]
    pub path_to_confile: PathBuf,

    /// Command to process
    #[command(subcommand)]
    #[arg()]
    pub command: Commands
}

/// The commands that are available
#[derive(Subcommand)]
pub enum Commands {
    /// Display the dnsblrsd configuration
    ShowConf {},

    /// Reconfigure a parameter of the dnsblrsd configuration
    #[command(subcommand)]
    EditConf (Subcommands),

    /// Get info about a matchclass
    GetInfo {matchclass: String},

    /// Add a new rule
    SetRule {
        rule: String,
        // "qtype" and "ip" are "Option"s because a rule can be set without them
        qtype: Option<String>,
        ip: Option<String>
    },

    /// Delete a rule or a complete matchclass
    DelRule {
        rule: String,
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
    ShowStats {pattern: String},

    /// Clear stats about IP addresses that match a pattern
    ClearStats {pattern: String}
}

/// The subcommands that modify the dnsblrsd configuration
#[derive(Subcommand)]
pub enum Subcommands {
    /// Add new binds
    AddBinds {binds: Vec<String>},

    /// Clear a parameter
    ClearParam {parameter: String},

    /// Overwrite the 2 forwarders
    Forwarders {forwarders: Vec<String>},

    /// Overwrite the 2 blackhole IPs
    BlackholeIps {blackhole_ips: Vec<String>},

    /// Add new blocked IPs
    BlockIps {blocked_ips: Vec<String>}
}
