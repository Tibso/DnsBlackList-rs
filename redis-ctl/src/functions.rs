use crate::Confile;

use std::{
    path::PathBuf,
    fs::File,
    io::{BufReader, BufRead},
    net::IpAddr
};
use anyhow::{Result, Context};
use redis::{Connection, Cmd, FromRedisValue, ConnectionLike};

fn hset (
    connection: &mut Connection,
    hash: String,
    field: &str,
    value: String
)
-> Result<usize> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg("HSET")
        .arg(hash)
        .arg(field)
        .arg(value)
    )?;
    let add_count = FromRedisValue::from_redis_value(&ser_answer)?;

    Ok(add_count)
}

fn del (
    connection: &mut Connection,
    hash: String
)
-> Result<usize> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg("DEL")
        .arg(hash))?;
    let del_count = FromRedisValue::from_redis_value(&ser_answer)?;

    Ok(del_count)
}

fn del_vec (
    connection: &mut Connection,
    hashes: Vec<String>
)
-> Result<usize> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg("DEL")
        .arg(hashes))?;
    let del_count = FromRedisValue::from_redis_value(&ser_answer)?;

    Ok(del_count)
}

fn hdel (
    connection: &mut Connection,
    hash: String,
    field: &str
)
-> Result<usize> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg("HDEl")
        .arg(hash)
        .arg(field))?;
    let del_count = FromRedisValue::from_redis_value(&ser_answer)?;

    Ok(del_count)
}

fn get_keys (
    connection: &mut Connection,
    command: &str,
    hash: String
)
-> Result<Vec<String>> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg(command)
        .arg(hash))?;
    let deser_answer = FromRedisValue::from_redis_value(&ser_answer)?;

    Ok(deser_answer)
}

pub fn show_conf (
    mut connection: Connection,
    confile: Confile
)
-> Result<()> {
    let binds = get_keys(&mut connection, "HKEYS", format!("binds:{}", confile.daemon_id))
        .with_context(|| format!("Error requesting binds"))?;
    let forwarders = get_keys(&mut connection, "HKEYS", format!("forwarders:{}", confile.daemon_id))
        .with_context(|| format!("Error requesting forwarders"))?;
    let matchclasses = get_keys(&mut connection, "HKEYS", format!("matchclasses:{}", confile.daemon_id))
        .with_context(|| format!("Error requesting matchclasses"))?;
    let blackhole_ips = get_keys(&mut connection, "HKEYS", format!("blackhole_ips:{}", confile.daemon_id))
        .with_context(|| format!("Error requesting blackhole_ips"))?;

    print!("{:#?}\nbinds {:#?}\nforwarders {:#?}\nmatchclasses {:#?}\nblackhole_ips {:#?}\n",
        confile, binds, forwarders, matchclasses, blackhole_ips
    );    

    Ok(())
}

pub fn clear_stats (
    mut connection: Connection,
    daemon_id: String,
    prefix: String
)
-> Result<()> {
    let hashes = get_keys(&mut connection, "KEYS", format!("stats:{daemon_id}:{prefix}"))
        .with_context(|| format!("Error requesting hashes"))?;

    let del_count = del_vec(&mut connection, hashes)
        .with_context(|| format!("Error deleting stats"))?;

    println!("{del_count} hashes were deleted");

    Ok(())
}

pub fn get_stats (
    mut connection: Connection,
    daemon_id: String,
    prefix: String
)
-> Result<()> {
    let hashes = get_keys(&mut connection, "KEYS", format!("stats:{daemon_id}:{prefix}"))
        .with_context(|| format!("Error requesting hashes"))?;

    for hash in hashes {
        let keys = get_keys(&mut connection, "HGETALL", hash.clone())
            .with_context(|| format!("Error requesting keys of hash: \"{hash}\""))?;

        let split: Vec<&str> = hash.split(':').collect();

        print!("Stats for hash: \"{}\"\n\n{:#?}\n", split[2], keys)
    }

    Ok(())
}

pub fn get_info (
    mut connection: Connection,
    matchclass: String
)
-> Result<()> {
    let fields = get_keys(&mut connection, "HKEYS", matchclass)
        .with_context(|| format!("Error requesting fields"))?;

    if fields.len() == 0 {
        println!("The matchclass doesn't exist or doesn't have any field")
    } else {
        print!("\n{fields:#?}\n")
    }

    Ok(())
}

pub fn drop_entries (
    mut connection: Connection,
    pattern: String
)
-> Result<()> {
    let hashes = get_keys(&mut connection, "KEYS", pattern)
        .with_context(|| format!("Error requesting hashes"))?;

    let del_count = del_vec(&mut connection, hashes)
        .with_context(|| format!("Error deleting hashes"))?;

    println!("{del_count} hashes were deleted");    

    Ok(())
}

pub fn dump_matchclass (
    mut connection: Connection,
    matchclass: String
)
-> Result<()> {
    let del_count = del(&mut connection, matchclass)
        .with_context(|| format!("Error deleting matchclass"))?;

    if del_count == 1 {
        println!("Matchclass sucessfully dumped");
    } else {
        println!("Unexpected response when deleting matchclass")
    }

    Ok(())
}

pub fn feed_matchclass (
    mut connection: Connection,
    path_to_list: PathBuf,
    matchclass: String
)
-> Result<()> {
    let file = File::open(path_to_list)?;

    let mut add_count = 0usize;
    let mut line_count = 0usize;
    let lines = BufReader::new(file).lines();
    for line in lines {
        line_count += 1;
        
        if let Ok(line) = line {
            let mut split = line.split(' ');

            let Some(domain_name) = split.next() else {
                continue
            };

            let mut is_both_default = true;

            if let Some(ip_1) = split.next() {
                is_both_default = false;

                match ip_1.parse::<IpAddr>() {
                    Ok(ok) => match ok.is_ipv4() {
                        true => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", ip_1.to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        false => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", ip_1.to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        }
                    },
                    Err(_) => match ip_1 {
                        "A" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", "1".to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        "AAAA" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", "1".to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        _ => println!("Error parsing {ip_1} item on line: {line_count}")
                    }
                };
            }

            if let Some(ip_2) = split.next() {
                is_both_default = false;

                match ip_2.parse::<IpAddr>() {
                    Ok(ok) => match ok.is_ipv6() {
                        true => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", ip_2.to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_2}\" on line: {line_count}")
                        },
                        false => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", ip_2.to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_2}\" on line: {line_count}")
                        }
                    },
                    Err(_) => match ip_2 {
                        "AAAA" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", "1".to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_2}\" on line: {line_count}")
                        },
                        "A" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", "1".to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_2}\" on line: {line_count}")
                        },
                        _ => println!("Error parsing {ip_2} item on line: {line_count}")
                    }
                }
            }

            if is_both_default {
                match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", "1".to_string()) {
                    Ok(ok) => add_count += ok,
                    Err(_) => println!("Error feeding matchclass with default A on line: {line_count}")
                }
                match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", "1".to_string()) {
                    Ok(ok) => add_count += ok,
                    Err(_) => println!("Error feeding matchclass with default AAAA on line: {line_count}")
                }
            }
        }
    }

    println!("{add_count} lines were fed");

    Ok(())
}

pub fn set_entry (
    mut connection: Connection,
    matchclass: String,
    qtype: Option<String>,
    ip: Option<String>
)
-> Result<()> {
    let mut add_count = 0usize;
    match qtype.as_deref() {
        Some("A") => {
            match ip {
                Some(_) => {
                    let ip = ip.unwrap().parse::<IpAddr>()
                        .with_context(|| format!("Error parsing ip address"))?;

                    if ip.is_ipv4() {
                        add_count += hset(&mut connection, matchclass.clone(), "A", ip.to_string())
                            .with_context(|| format!("Error adding matchclass: \"{matchclass}\" with record type: \"A\""))?
                    } else {
                        println!("Provided IP was not v4")
                    }
                },
                None => add_count += hset(&mut connection, matchclass.clone(), "A", "1".to_string())
                    .with_context(|| format!("Error adding matchclass: \"{matchclass}\" with record type: \"A\""))?
            }
        },
        Some("AAAA") => {
            match ip {
                Some(_) => {
                    let ip = ip.unwrap().parse::<IpAddr>()
                        .with_context(|| format!("Error parsing ip address"))?;

                    if ip.is_ipv6() {
                        add_count += hset(&mut connection, matchclass.clone(), "AAAA", ip.to_string())
                            .with_context(|| format!("Error adding matchclass: \"{matchclass}\" with record type: \"AAAA\""))?
                    } else {
                        println!("Provided IP was not v6")
                    }
                },
                None => add_count += hset(&mut connection, matchclass.clone(), "AAAA", "1".to_string())
                    .with_context(|| format!("Error adding matchclass: \"{matchclass}\" with record type: \"AAAA\""))?
            }
        },
        Some(_) => println!("Invalid record type was provided"),
        None => {
            println!("Record type not provided, adding default rule for both v4 and v6");

            add_count += hset(&mut connection, matchclass.clone(), "A", "1".to_string())
                .with_context(|| format!("Error adding matchclass: \"{matchclass}\" with record type: \"A\""))?;
            add_count += hset(&mut connection, matchclass.clone(), "AAAA", "1".to_string())
                .with_context(|| format!("Error adding matchclass: \"{matchclass}\" with record type: \"AAAA\""))?
        }
    }

    println!("{add_count} rules were added");

    Ok(())
}

pub fn delete_entry (
    mut connection: Connection,
    matchclass: String,
    qtype: Option<String>
)
-> Result<()> {
    let mut del_count = 0usize;
    match qtype.as_deref() {
        Some("A") => del_count += hdel(&mut connection, matchclass.clone(), "A")
            .with_context(|| format!("Error deleting matchclass: \"{matchclass}\" with record type: \"A\""))?,
        Some("AAAA") => del_count += hdel(&mut connection, matchclass.clone(), "AAAA")
        .with_context(|| format!("Error deleting matchclass: \"{matchclass}\" with record type: \"AAAA\""))?,
        Some(_) => println!("Invalid record type provided"),
        _ => {
            println!("Record type not provided, deleting rule for both v4 and v6");

            del_count += hdel(&mut connection, matchclass.clone(), "A")
                .with_context(|| format!("Error deleting matchclass: \"{matchclass}\" with record type: \"A\""))?;
            del_count += hdel(&mut connection, matchclass.clone(), "AAAA")
                .with_context(|| format!("Error deleting matchclass: \"{matchclass}\" with record type: \"AAAA\""))?
        }
    }

    println!("{del_count} rules were deleted");

    Ok(())
}
