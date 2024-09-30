use std::path::PathBuf;
use clap::{Parser, Subcommand};

/// The structure clap will parse
#[derive(Parser)]
#[command(about = "This is a command-line tool used to manipulate the Redis blacklist", long_about = None)]
pub struct Args {
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
    /// Display the daemon's configuration and the 'redis-ctl' version
    ShowConf {},

    /// Reconfigure a parameter of the daemon's configuration
    #[command(subcommand)]
    EditConf (Subcommands),

    /// Add a new rule
    AddRule {
        filter: String,
        source: String,
        domain: String,
        ip1: Option<String>,
        ip2: Option<String>
    },

    /// Delete a rule or either of its v4 or v6 IPs
    DelRule {
        filter: String,
        domain: String,
        ip: Option<String>
    },

    /// Search for rules using a pattern
    SearchRules {
        filter: String,
        domain: String
    },

    /// Disable rules that match a pattern
    DisableRules {
        filter: String,
        pattern: String
    },

    /// Enable rules that match a pattern
    EnableRules {
        filter: String,
        pattern: String
    },

    /// Update rules automatically using the "dnsblrs_sources.json" file
    AutoFeed {path_to_sources: PathBuf},
    
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

    /// Remove binds
    RemoveBinds {binds: Vec<String>},

    /// Add new forwarders
    AddForwarders {forwarders: Vec<String>},

    /// Remove forwarders
    RemoveForwarders {forwarders: Vec<String>},

    /// Overwrite the 2 sinks
    SetSinks {sinks: Vec<String>},

    /// Add new blocked IPs
    AddBlockedIps {blocked_ips: Vec<String>},

    ///Removed blocked IPs
    RemoveBlockedIps {blocked_ips: Vec<String>},

    /// Add filters
    AddFilters {filters: Vec<String>},

    /// Remove filters
    RemoveFilters {filters: Vec<String>}
}
