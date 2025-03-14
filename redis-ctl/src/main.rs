#![forbid(unsafe_code)]

mod commands;
mod modules;

use crate::{commands::{Args, Commands, Subcommands}, modules::{conf, stats, rules}};

use redis::Client;
use std::{fs, process::ExitCode};
use clap::Parser;
use serde::{Serialize, Deserialize};

/// The confile structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Confile {
    daemon_id: String,
    redis_addr: String
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    // Arguments are parsed and stored
    let args = Args::parse();
    let path_to_confile = &args.path_to_confile;

    // First argument should be the 'path_to_confile'
    let (daemon_id, redis_addr) = {
        let tmp_string = match fs::read_to_string(path_to_confile) {
            Ok(string) => string,
            Err(err) => {
                println!("Error reading file from {path_to_confile:?}: {err}");
                return ExitCode::from(78) // CONFIG
            }
        };
        let confile: Confile = match serde_json::from_str(tmp_string.as_str()) {
            Ok(confile) => confile,
            Err(err) => {
                println!("Error deserializing config file data: {err}");
                return ExitCode::from(78) // CONFIG
            }
        };
        (confile.daemon_id, confile.redis_addr)
    };
    let (daemon_id, redis_addr) = (daemon_id.as_str(), redis_addr.as_str());

    // A client is built and probes the Redis server to check its availability
    let client = match Client::open(format!("redis://{redis_addr}/")) {
        Ok(client) => client,
        Err(err) => {
            println!("Error probing the Redis server: {err}");
            return ExitCode::from(68) // NOHOST
        }
    };
    let mut connection = match client.get_connection() {
        Ok(connection) => connection,
        Err(err) => {
            println!("Error creating the connection: {err}");
            return ExitCode::from(69) // UNAVAILABLE
        }
    };

    // Second argument should be the command to use
    // Each element of the Commands enum calls its own function
    let result = match args.command {
        Commands::ShowConf { }
            => conf::show(&mut connection, daemon_id, redis_addr),

        Commands::EditConf (subcommand)
            => match subcommand {
                Subcommands::AddBinds { binds }
                    => conf::add_binds(&mut connection, daemon_id, binds),

                Subcommands::RemoveBinds { binds }
                    => conf::remove_binds(&mut connection, daemon_id, binds),

                Subcommands::AddForwarders { forwarders }
                    => conf::add_forwarders(&mut connection, daemon_id, forwarders),

                Subcommands::RemoveForwarders { forwarders }
                    => conf::remove_forwarders(&mut connection, daemon_id, forwarders),

                Subcommands::AddFilters { filters }
                    => conf::add_filters(&mut connection, daemon_id, filters),

                Subcommands::RemoveFilters { filters }
                    => conf::remove_filters(&mut connection, daemon_id, filters)
            },

        Commands::ClearStats { pattern }
            => stats::clear(&mut connection, daemon_id, &pattern),

        Commands::ShowStats { pattern }
            => stats::show(&mut connection, daemon_id, &pattern),

        Commands::SearchRules { filter, domain }
            => rules::search(&mut connection, &filter, &domain),

        Commands::DisableRules { filter, pattern }
            => rules::disable(&mut connection, &filter, &pattern),

        Commands::EnableRules { filter, pattern }
            => rules::enable(&mut connection, &filter, &pattern),

        Commands::AddIps { source, filter, ttl, ips }
            => rules::add_ips(&mut connection, &source, &filter, &ttl, ips),

        Commands::RemoveIps { filter, ips }
            => rules::remove_ips(&mut connection, &filter, ips),

        Commands::FeedFilter { path_to_list, source, filter, ttl }
            => rules::feed_filter(&mut connection, &path_to_list, &source, &filter, &ttl),

        Commands::AddDomain { filter, source, domain, ttl, ip1, ip2 }
            => rules::add_domain(&mut connection, &filter, &source, &domain, &ttl, ip1, ip2),

        Commands::RemoveDomain { filter, domain, ip_ver }
            => rules::remove_domain(&mut connection, &filter, &domain, ip_ver),
    };

    match result {
        Ok(exitcode) => exitcode,
        Err(err) => {
            println!("{err}");
            ExitCode::from(1)
        }
    }
}
