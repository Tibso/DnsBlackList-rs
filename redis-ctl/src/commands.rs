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
    /// Add a new domain rule
    AddDomain {
        source: String,
        filter: String,
        domain: String,
        ttl: String,
        ip1: Option<String>,
        ip2: Option<String>
    },

    /// Delete a domain rule or either of its v4 or v6 IPs
    RemoveDomain {
        filter: String,
        domain: String,
        ip_ver: Option<u8>
    },

    /// Search rules using a pattern
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

    /// Add new IP rules
    AddIps {
        source: String,
        filter: String,
        ttl: String,
        ips: Vec<String>
    },

    /// Remove IP rules
    RemoveIps {
        filter: String,
        ips: Vec<String>
    },

    /// Feed rules to a filter
    FeedFilter {
        path_to_list: PathBuf,
        source: String,
        filter: String,
        ttl: String
    },

    // /// Display stats about IP addresses that match a pattern
    // ShowStats {pattern: String},

    // /// Clear stats about IP addresses that match a pattern
    // ClearStats {pattern: String},
}
