mod handler_mod;
mod redis_mod;
mod resolver_mod;

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

#[tokio::main]
async fn main()
-> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    let config: Config = {
        let data = fs::read_to_string("resolver.conf").expect("Error reading config file");
        serde_json::from_str(&data).expect("Error deserializing config file data")
    };
    let daemon_id = config.daemon_id;
    println!("Daemon_id is {}", daemon_id);
    
    let redis_address = config.redis_address;
    println!("Redis server: {}", redis_address);
    let redis_client = redis::Client::open(format!("redis://{}/", redis_address)).expect("Error probing the Redis server");
    println!("Redis server probe successful");
    let redis_manager = redis_client.get_tokio_connection_manager().await.expect("Error initiating the connection manager");
    println!("Connection to Redis successful");

    let matchclasses = redis_mod::redis_get(&redis_manager, "matchclasses", &daemon_id).await.expect("Error fetching matchclasses from Redis");
    let matchclasses_count = matchclasses.clone().iter().count();
    println!("Received {} matchclasses", matchclasses_count);
    let binds = redis_mod::redis_get(&redis_manager, "binds", &daemon_id).await.expect("Error fetching binds from Redis");
    println!("Received bind list");

    println!("Initializing server...");
    let handler = handler_mod::Handler {
        redis_manager, matchclasses
    };
    let mut server = ServerFuture::new(handler);

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
    println!("{} binds set out of {} total binds", successful_bind_count, binds_count);

    println!("Started {}", daemon_id);
    server.block_until_done().await?;

    Ok(())
}