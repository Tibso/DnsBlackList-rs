mod commands;
mod modules;

use crate::{commands::{Args, Commands, Subcommands}, modules::{conf, feed, stats, rules}};

use redis::Client;
use std::{fs, process::ExitCode};
use clap::Parser;
use serde::{Serialize, Deserialize};

/// The confile structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Confile {
    daemon_id: String,
    redis_address: String
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    // Arguments are parsed and stored
    let args = Args::parse();
    let path_to_confile = &args.path_to_confile;

    // First argument should be the 'path_to_confile'
    let (daemon_id, redis_address) = {
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
        (confile.daemon_id, confile.redis_address)
    };
    let (daemon_id, redis_address) = (daemon_id.as_str(), redis_address.as_str());

    // A client is built and probes the Redis server to check its availability
    let client = match Client::open(format!("redis://{redis_address}/")) {
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
            => conf::show(&mut connection, daemon_id, redis_address),

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

                Subcommands::SetSinks { sinks }
                    => conf::set_sinks(&mut connection, daemon_id, sinks),

                Subcommands::AddBlockedIps { blocked_ips }
                    => conf::add_blocked_ips(&mut connection, daemon_id, blocked_ips),

                Subcommands::RemoveBlockedIps { blocked_ips }
                    => conf::remove_blocked_ips(&mut connection, daemon_id, blocked_ips),

                Subcommands::AddFilters { filters }
                    => conf::add_filters(&mut connection, daemon_id, filters),

                Subcommands::RemoveFilters { filters }
                    => conf::remove_filters(&mut connection, daemon_id, filters)
            },

        Commands::ClearStats { pattern }
            => stats::clear(&mut connection, daemon_id, pattern.as_str()),

        Commands::ShowStats { pattern }
            => stats::show(&mut connection, daemon_id, pattern.as_str()),

        Commands::SearchRules { filter, domain }
            => rules::search(&mut connection, filter.as_str(), domain.as_str()),

        Commands::DisableRules { filter, pattern }
            => rules::disable(&mut connection, filter.as_str(), pattern.as_str()),

        Commands::EnableRules { filter, pattern }
            => rules::enable(&mut connection, filter.as_str(), pattern.as_str()),

        Commands::AutoFeed { path_to_srcs }
            => feed::auto(&mut connection, &path_to_srcs),

        Commands::Feed { path_to_list, filter, src }
            => feed::add_to_filter(&mut connection, &path_to_list, filter.as_str(), src.as_str()),

        Commands::AddRule { filter, src, domain, ip1, ip2 }
            => rules::add(&mut connection, filter.as_str(), src.as_str(), domain.as_str(), ip1, ip2),

        Commands::DelRule { filter, domain, ip }
            => rules::delete(&mut connection, filter.as_str(), domain.as_str(), ip),
    };

    match result {
        Ok(exitcode) => exitcode,
        Err(err) => {
            println!("{err}");
            ExitCode::from(1)
        }
    }
}
