mod commands;
mod modules;
mod redis_mod;

use crate::{
    commands::{Cli, Commands, Subcommands},
    modules::{conf, feed, stats, rules}
};

//use modules::backup;
use redis::Client;

use std::{fs, process::ExitCode};
use clap::Parser;
use serde::{Serialize, Deserialize};

/// The configuration file structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Confile {
    daemon_id: String,
    redis_address: String
}

fn main() -> ExitCode {
    // Arguments are parsed and stored in the Cli struct
    let cli = Cli::parse();

    // First argument should be the path_to_confile
    let confile: Confile = {
        let tmp_string = match fs::read_to_string(&cli.path_to_confile) {
            Ok(ok) => ok,
            Err(err) => {
                println!("Error reading file from: {:?}: {err}", cli.path_to_confile, );
                // CONFIG exitcode on error
                return ExitCode::from(78)
            }
        };
        match serde_json::from_str(&tmp_string) {
            Ok(ok) => ok,
            Err(err) => {
                println!("Error deserializing config file data: {err}", );
                // CONFIG exitcode on error
                return ExitCode::from(78)
            }
        }
    };
    
    // A client is built and probes the Redis server to check its availability
    let client = match Client::open(format!("redis://{}/", confile.redis_address)) {
        Ok(ok) => ok,
        Err(err) => {
            println!("Error probing the Redis server: {err}", );
            // NOHOST exitcode on error
            return ExitCode::from(68)
        }
    };
    let connection = match client.get_connection() {
        Ok(ok) => ok,
        Err(err) => {
            println!("Error creating the connection: {err}", );
            // UNAVAILABLE exitcode on error
            return ExitCode::from(69) // NICE
        }
    };

    // Second argument should be the command to use
    // Each element of the "Commands" enum calls its own function
    let result = match &cli.command {
        Commands::ShowConf {}
            => conf::show(connection, &confile),

        Commands::EditConf (subcommand)
            => match subcommand {
                Subcommands::AddBinds {binds}
                    => conf::add_binds(connection, &confile.daemon_id, binds.to_owned()),

                Subcommands::ClearParam {parameter}
                    => conf::clear_parameter(connection, &confile.daemon_id, parameter),

                Subcommands::AddForwarders {forwarders}
                    => conf::add_forwarders(connection, &confile.daemon_id, forwarders.to_owned()),

                Subcommands::Blackholes {blackhole_ips}
                    => conf::set_blackholes(connection, &confile.daemon_id, blackhole_ips.to_owned()),

                Subcommands::AddBlockedIps {blocked_ips}
                    => conf::add_blocked_ips(connection, &confile.daemon_id, blocked_ips.to_owned()),

                Subcommands::AddFilters {filters}
                    => conf::add_filters(connection, &confile.daemon_id, filters.to_owned()),

                Subcommands::RemoveFilters {filters}
                    => conf::remove_filters(connection, &confile.daemon_id, filters.to_owned())
            },

        Commands::ClearStats {pattern}
            => stats::clear(connection, pattern),

        Commands::ShowStats {pattern}
            => stats::show(connection, pattern),

        Commands::SearchRule {filter, domain}
            => rules::search(connection, filter, domain),

        Commands::DisableRules {pattern}
            => rules::disable(connection, pattern),

        Commands::EnableRules {pattern}
            => rules::enable(connection, pattern),

        Commands::AutoFeed {path_to_sources}
            => feed::auto(connection, path_to_sources.to_owned()),

        Commands::Feed {path_to_list, filter, source}
            => feed::add_to_filter(connection, path_to_list, filter, source),

        Commands::SetRule {filter, source, domain, ips}
            => rules::set(connection, filter, source, domain, ips.to_owned()),

        Commands::DelRule {filter, domain, ip}
            => rules::delete(connection, filter, domain, ip.to_owned()),
        
//       Commands::BackupFull {path_to_backup}
//            => backup::create_full(connection, path_to_backup)
    };

    match result {
        Ok(exitcode) => exitcode,
        Err(err) => {
            println!("{err}");
            ExitCode::from(1)
        }
    }
}
