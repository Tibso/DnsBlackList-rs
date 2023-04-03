mod commands;
mod functions;

use commands::{Cli, Commands};

use anyhow::{Context, Result};
use std::fs;
use clap::Parser;
use redis::Client;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Confile {
    daemon_id: String,
    redis_address: String
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let confile: Confile = {
        let tmp_string = fs::read_to_string(&cli.path_to_confile)
            .with_context(|| format!("Failed to read file from: {:?}", cli.path_to_confile))?;
        serde_json::from_str(&tmp_string)?
    };
    
    let client = Client::open(format!("redis://{}/", confile.redis_address))?;
    let connection = client.get_connection()?;

    return match &cli.command {
        Commands::Showconf {}
            => functions::show_conf(
                connection, confile
            ),
        Commands::Clear {prefix}
            => functions::clear_stats(
                connection, confile.daemon_id, prefix.to_owned()
            ),
        Commands::Stats {prefix}
            => functions::get_stats(
                connection, confile.daemon_id, prefix.to_owned()
            ),
        Commands::Get {matchclass}
            => functions::get_info(
                connection, matchclass.to_owned()
            ),
        Commands::Drop {pattern}
            => functions::drop_entries(
                connection, pattern.to_owned()
            ),
        Commands::Dump {matchclass}
            => functions::dump_matchclass(
                connection, matchclass.to_owned()
            ),
        Commands::Feed {path_to_list, matchclass}
            => functions::feed_matchclass(
                connection, path_to_list.to_owned(), matchclass.to_owned()
            ),
        Commands::Set {matchclass, qtype, ip}
            => functions::set_entry(
                connection, matchclass.to_owned(), qtype.to_owned(), ip.to_owned()
            ),
        Commands::Delete {matchclass, qtype}
            => functions::delete_entry(
                connection, matchclass.to_owned(), qtype.to_owned()
            )
    }
}
