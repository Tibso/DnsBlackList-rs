mod handler_mod;
mod redis_mod;
mod resolver_mod;

use crate::handler_mod::Handler;

use trust_dns_server::ServerFuture;
use tokio::net::{TcpListener, UdpSocket};
use std::{
    time::Duration,
    fs,
    error::Error
};
use serde::{Serialize, Deserialize};

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize, Debug)]
struct Config { 
    daemon_id: String,
    redis_address: String
}

fn read_config (
    file_name: &str
)
-> (String, String) {
    let config: Config = {
        let data = fs::read_to_string(file_name).expect("Error reading config file");
        serde_json::from_str(&data).expect("Error deserializing config file data")
    };
    let daemon_id = config.daemon_id;
    println!("Daemon_id is {}", daemon_id);

    let redis_address = config.redis_address;
    println!("Redis server: {}", redis_address);

    return (daemon_id, redis_address)
}

async fn setup_binds (
    server: &mut ServerFuture<Handler>,
    binds: Vec<String>
) {
    let binds_count = binds.clone().iter().count();
    let mut successful_bind_count: u32 = 0;
    for bind in binds {
        let splits: Vec<&str> = bind.split("=").collect();

        match splits[0] {
            "UDP" => {
                let socket: UdpSocket;
                match UdpSocket::bind(splits[1]).await {
                    Ok(ok) => socket = ok,
                    Err(_) => continue
                };
                server.register_socket(socket)
            },
            "TCP" => {
                let listener: TcpListener;
                match TcpListener::bind(splits[1]).await {
                    Ok(ok) => listener = ok,
                    Err(_) => continue
                };
                server.register_listener(listener, TCP_TIMEOUT)
            },
            _ => {continue}
        };
        successful_bind_count += 1
    }
    println!("{} out of {} total binds were set", successful_bind_count, binds_count);
}

#[tokio::main]
async fn main()
-> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let (daemon_id, redis_address) = read_config("dnslr.conf");

    let (redis_manager, matchclasses, forwarders, binds) = redis_mod::build_redis(redis_address, &daemon_id).await;

    let resolver = resolver_mod::build_resolver(forwarders);

    println!("Initializing server...");
    let handler = handler_mod::Handler {
        redis_manager, matchclasses, resolver
    };
    let mut server = ServerFuture::new(handler);

    setup_binds(&mut server, binds).await;

    println!("Started {}", daemon_id);
    server.block_until_done().await?;

    Ok(())
}
