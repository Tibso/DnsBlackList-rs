#![forbid(unsafe_code)]

mod commands;
mod modules;

use crate::{commands::{Args, Commands}, modules::rules};
use dnsblrsd::config::Config;

use clap::Parser;
use redis::Client;
use std::{fs, process::ExitCode};
use serde_norway::from_str;

fn main() -> ExitCode {
    // Arguments are parsed and stored
    let args = Args::parse();
    let path_to_confile = &args.path_to_confile;

    // First argument should be the 'path_to_confile'
    let redis_addr = {
        let data = match fs::read_to_string(path_to_confile) {
            Ok(data) => data,
            Err(e) => {
                println!("Error reading file from {path_to_confile:?}: {e}");
                return ExitCode::from(78) // CONFIG
            }
        };
        let config: Config = match from_str(data.as_str()) {
            Ok(config) => config,
            Err(e) => {
                println!("Error deserializing config file data: {e}");
                return ExitCode::from(78) // CONFIG
            }
        };
        config.redis_addr.to_string()
    };

    let client = match Client::open(format!("redis://{redis_addr}/")) {
        Ok(client) => client,
        Err(e) => {
            println!("Error probing the Redis server: {e}");
            return ExitCode::from(68) // NOHOST
        }
    };
    let mut con = match client.get_connection() {
        Ok(con) => con,
        Err(e) => {
            println!("Error creating the connection: {e}");
            return ExitCode::from(69) // UNAVAILABLE
        }
    };

    // Second argument should be the command to use
    // Each element of the Commands enum calls its own function
    let result = match args.command {
        //Commands::ClearStats { pattern }
        //    => stats::clear(&mut connection, daemon_id, &pattern),
        //
        //Commands::ShowStats { pattern }
        //    => stats::show(&mut connection, daemon_id, &pattern),

        Commands::SearchRules { filter, domain }
            => rules::search(&mut con, &filter, &domain),

        Commands::DisableRules { filter, pattern }
            => rules::disable(&mut con, &filter, &pattern),

        Commands::EnableRules { filter, pattern }
            => rules::enable(&mut con, &filter, &pattern),

        Commands::AddIps { source, filter, ttl, ips }
            => rules::add_ips(&mut con, &source, &filter, &ttl, ips),

        Commands::RemoveIps { filter, ips }
            => rules::remove_ips(&mut con, &filter, ips),

        Commands::FeedFilter { path_to_list, source, filter, ttl }
            => rules::feed_filter(&mut con, &path_to_list, &source, &filter, &ttl),

        Commands::AddDomain { filter, source, domain, ttl, ip1, ip2 }
            => rules::add_domain(&mut con, &filter, &source, &domain, &ttl, ip1, ip2),

        Commands::RemoveDomain { filter, domain, ip_ver }
            => rules::remove_domain(&mut con, &filter, &domain, ip_ver),
    };

    match result {
        Ok(exitcode) => exitcode,
        Err(e) => {
            println!("{e}");
            ExitCode::from(1)
        }
    }
}
