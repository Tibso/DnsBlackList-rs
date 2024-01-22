use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// The structure "clap" will parse
#[derive(Parser)]
#[command(about = "This is a command-line tool used to manipulate the Redis blacklist", long_about = None)]
pub struct Cli {
    /// Path to "dnsblrsd.conf" is required
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
    /// Display the daemon's configuration
    ShowConf {},

    /// Reconfigure a parameter of the daemon's configuration
    #[command(subcommand)]
    EditConf (Subcommands),

    /// Add a new rule
    SetRule {
        filter: String,
        source: String,
        domain: String,
        ips: Option<Vec<String>>
    },

    /// Delete a rule or a complete filter
    DelRule {
        filter: String,
        domain: String,
        ip: Option<String>
    },

    /// Search for a rule
    SearchRule {
        filter: String,
        domain: String
    },

    /// Disable rules that match a pattern
    DisableRules {pattern: String},

    /// Enable rules that match a pattern
    EnableRules {pattern: String},

    /// Update rules automatically using the sources defined in the "dnsblrsd_sources.json" file
    AutoFeed {
        path_to_sources: PathBuf
    },
    /// Feed a list of domains to a matchclass
    Feed {
        path_to_list: PathBuf,
        filter: String,
        source: String
    },
    /// Display stats about IP addresses that match a pattern
    ShowStats {pattern: String},

    /// Clear stats about IP addresses that match a pattern
    ClearStats {pattern: String},

    //BackupFull {path_to_backup: String}
}

/// The subcommands that modify the dnsblrsd configuration
#[derive(Subcommand)]
pub enum Subcommands {
    /// Add new binds
    AddBinds {binds: Vec<String>},

    /// Clear a parameter
    ClearParam {parameter: String},

    /// Add new forwarders
    AddForwarders {forwarders: Vec<String>},

    /// Overwrite the 2 blackhole IPs
    Blackholes {blackhole_ips: Vec<String>},

    /// Add new blocked IPs
    AddBlockedIps {blocked_ips: Vec<String>},

    /// Add matchclass types
    AddFilters {filters: Vec<String>},

    /// Remove matchclass types
    RemoveFilters {filters: Vec<String>}
}
