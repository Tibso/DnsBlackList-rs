use crate::Confile;

use std::{
    path::PathBuf, fs::File, net::IpAddr,
    io::{BufReader, BufRead},
    process::ExitCode
};
use redis::{Connection, Cmd, FromRedisValue, ConnectionLike, RedisResult};

/// Sets a value of a field in a hash in Redis
fn hset (
    connection: &mut Connection,
    hash: String,
    field: &str,
    value: String
)
-> RedisResult<usize> {
    // This Redis command sets a value of a field in a hash if it does not already exist
    // The command returns the number of values added in a serialized "Value"
    let ser_answer = connection.req_command(Cmd::new()
        .arg("HSET")
        .arg(hash)
        .arg(field)
        .arg(value)
    )?;
    // Deserializes "Value"
    let add_count = FromRedisValue::from_redis_value(&ser_answer)?;

    // Returns 1 if the field was successfully added
    Ok(add_count)
}

/// Deletes hashes from Redis
fn del_vec (
    connection: &mut Connection,
    hashes: Vec<String>
)
-> RedisResult<usize> {
    // This Redis command deletes hashes if they exists
    // The command takes a vector as input
    let ser_answer = connection.req_command(Cmd::new()
        .arg("DEL")
        .arg(hashes))?;
    let del_count = FromRedisValue::from_redis_value(&ser_answer)?;

    // Returns the amount of hashes deleted
    Ok(del_count)
}

/// Deletes the field of a hash from Redis
fn hdel (
    connection: &mut Connection,
    hash: String,
    field: &str
)
-> RedisResult<usize> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg("HDEl")
        .arg(hash)
        .arg(field))?;
    let del_count = FromRedisValue::from_redis_value(&ser_answer)?;

    // Returns 1 if the field was successfully deleted
    Ok(del_count)
}

/// Fetches all the keys of a hash from Redis
fn get_keys (
    connection: &mut Connection,
    command: &str,
    hash: String
)
-> RedisResult<Vec<String>> {
    let ser_answer = connection.req_command(Cmd::new()
        .arg(command)
        .arg(hash))?;
    let deser_answer = FromRedisValue::from_redis_value(&ser_answer)?;

    // Returns a vector of strings
    Ok(deser_answer)
}

/// Displays the daemon's configuration
pub fn show_conf (
    mut connection: Connection,
    confile: Confile
)
-> RedisResult<ExitCode> {
    // Retrives the daemon's configuration as the server would when starting
    let binds = get_keys(&mut connection, "HKEYS", format!("binds:{}", confile.daemon_id))?;
    let forwarders = get_keys(&mut connection, "HKEYS", format!("forwarders:{}", confile.daemon_id))?;
    let matchclasses = get_keys(&mut connection, "HKEYS", format!("matchclasses:{}", confile.daemon_id))?;
    let blackhole_ips = get_keys(&mut connection, "HKEYS", format!("blackhole_ips:{}", confile.daemon_id))?;

    print!("{:#?}\nbinds {:#?}\nforwarders {:#?}\nmatchclasses {:#?}\nblackhole_ips {:#?}\n",
        confile, binds, forwarders, matchclasses, blackhole_ips
    );

    Ok(ExitCode::SUCCESS)
}

/// Deletes all stats that match an IP pattern
pub fn clear_stats (
    mut connection: Connection,
    daemon_id: String,
    pattern: String
)
-> RedisResult<ExitCode> {
    // Fetches all stats that match the "daemon_id" and the provided pattern
    let hashes = get_keys(&mut connection, "KEYS", format!("stats:{daemon_id}:{pattern}"))?;

    // Deletes all stats found
    let del_count = del_vec(&mut connection, hashes)?;

    println!("{del_count} hashes were deleted");

    Ok(ExitCode::SUCCESS)
}

/// Displays all stats that match an IP pattern
pub fn get_stats (
    mut connection: Connection,
    daemon_id: String,
    pattern: String
)
-> RedisResult<ExitCode> {
    // Fetches all stats that match the "daemon_id" and the provided pattern
    let hashes = get_keys(&mut connection, "KEYS", format!("stats:{daemon_id}:{pattern}"))?;

    // Fetches all the fields and values of each hash
    for hash in hashes {
        let keys = get_keys(&mut connection, "HGETALL", hash.clone())?;

        let split: Vec<&str> = hash.split(':').collect();

        print!("Stats for hash: \"{}\":\n{:#?}\n", split[2], keys)
    }

    Ok(ExitCode::SUCCESS)
}

/// Displays the info of a matchclass
pub fn get_info (
    mut connection: Connection,
    matchclass: String
)
-> RedisResult<ExitCode> {
    // Fetches all the fields of a matchclass
    let fields = get_keys(&mut connection, "HGETALL", matchclass)?;

    if fields.len() == 0 {
        println!("The matchclass doesn't exist or doesn't have any field")
    } else {
        println!("{fields:#?}")
    }

    Ok(ExitCode::SUCCESS)
}

/// Deletes all matchclasses that match a pattern
pub fn drop_matchclasses (
    mut connection: Connection,
    pattern: String
)
-> RedisResult<ExitCode> {
    // Fetches all matchclasses that match a pattern
    let hashes = get_keys(&mut connection, "KEYS", pattern)?;

    // Deletes all found matchclasses using a vector as input
    let del_count = del_vec(&mut connection, hashes)?;

    println!("{del_count} hashes were deleted");    

    Ok(ExitCode::SUCCESS)
}

/// Feeds a list of domain to a matchclass
pub fn feed_matchclass (
    mut connection: Connection,
    path_to_list: PathBuf,
    matchclass: String
)
-> RedisResult<ExitCode> {
    // Attempts to open the file
    let file = File::open(path_to_list)?;

    let mut add_count = 0usize;
    let mut line_count = 0usize;
    // Initializes a buffered reader and stores an iterator of its lines
    // This reader reads the file dynamically by reading big chunks of the file
    let lines = BufReader::new(file).lines();
    for line in lines {
        line_count += 1;

        // If the line was read succesfully
        if let Ok(line) = line {
            // The line is made iterable using the space as split character
            let mut split = line.split(' ');

            // First split should be the "domain_name"
            let Some(domain_name) = split.next() else {
                continue
            };

            // Variable that stores whether or not the both v4 and v6 rules should be set to default
            let mut is_both_default = true;

            // If an additionnal value was given to the command
            if let Some(ip_1) = split.next() {
                // The default values should not be used
                is_both_default = false;

                // Tries to parse it to an IP address
                match ip_1.parse::<IpAddr>() {
                    // If the parsing was successful, value is an IP and is not the default value
                    Ok(ok) => match ok.is_ipv4() {
                        // If the IP is v4, set the approriate rule
                        true => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", ip_1.to_string()) {
                            // If the command was successful, we add the number of rules set by the command to the counter
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        // If not v4 then v6
                        false => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", ip_1.to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        }
                    },
                    // If the parsing failed, the value should be a default value
                    Err(_) => match ip_1 {
                        // If the value is the default for v4
                        "A" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", "1".to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        // If not default v4 then v6
                        "AAAA" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", "1".to_string()) {
                            Ok(ok) => add_count += ok,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        // Couldn't parse the value
                        _ => println!("Error parsing {ip_1} item on line: {line_count}")
                    }
                };
            }

            // Ditto as first value, but tries to parse v6 first as user would most likely input v6 after v4
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

            // If 1 default or 1 IP weren't provided, both IPs are set as default
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

    Ok(ExitCode::SUCCESS)
}

/// Adds a new rule
pub fn set_rule (
    mut connection: Connection,
    matchclass: String,
    // "qtype" and "ip" are "Option"s because a rule can be set without them
    qtype: Option<String>,
    ip: Option<String>
)
-> RedisResult<ExitCode> {
    let mut add_count = 0usize;

    // Checks if "qtype" is provided, if it is, tries to parse the approriate "ip" Option
    match qtype.as_deref() {
        // If "qtype" specifies v4
        Some("A") => {
            match ip {
                // If "ip" value was provided
                Some(_) => {
                    // Tries to parse it
                    let ip = match ip.unwrap().parse::<IpAddr>() {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!("Error parsing IpAddr: {:?}", err);
                            return Ok(ExitCode::from(65))
                        }
                    };

                    // Provided "ip" must be v4
                    if ip.is_ipv4() {
                        add_count += hset(&mut connection, matchclass.clone(), "A", ip.to_string())?
                    } else {
                        println!("Provided IP was not v4")
                    }
                },
                // If "ip" value not provided, sets a default rule for v4
                None => add_count += hset(&mut connection, matchclass.clone(), "A", "1".to_string())?
            }
        },
        // If "qtype" specifies v6
        Some("AAAA") => {
            match ip {
                Some(_) => {
                    let ip = match ip.unwrap().parse::<IpAddr>(){
                        Ok(ok) => ok,
                        Err(err) => {
                            println!("Error parsing IpAddr: {:?}", err);
                            return Ok(ExitCode::from(65))
                        }
                    };

                    // Provided "ip" must be v6
                    if ip.is_ipv6() {
                        add_count += hset(&mut connection, matchclass.clone(), "AAAA", ip.to_string())?
                    } else {
                        println!("Provided IP was not v6")
                    }
                },
                // If "ip" value not provided, sets a default rule for v6
                None => add_count += hset(&mut connection, matchclass.clone(), "AAAA", "1".to_string())?
            }
        },
        // Provided "qtype" was not "A" or "AAAA" so it is incorrect
        Some(_) => println!("Invalid record type was provided"),
        // "qtype" was not provided, the default rules are added for both types
        None => {
            println!("Record type not provided, adding default rule for both v4 and v6");

            add_count += hset(&mut connection, matchclass.clone(), "A", "1".to_string())?;
            add_count += hset(&mut connection, matchclass.clone(), "AAAA", "1".to_string())?
        }
    }

    println!("{add_count} rules were added");

    Ok(ExitCode::SUCCESS)
}

/// Deletes a rule
pub fn delete_rule (
    mut connection: Connection,
    matchclass: String,
    qtype: Option<String>
)
-> RedisResult<ExitCode> {
    let mut del_count = 0usize;

    // Checks if "qtype" is provided, if it is, tries to delete the approriate rule
    match qtype.as_deref() {
        // If "qtype" specifies v4
        Some("A") => del_count += hdel(&mut connection, matchclass.clone(), "A")?,
            // If "qtype" specifies v6
        Some("AAAA") => del_count += hdel(&mut connection, matchclass.clone(), "AAAA")?,
        Some(_) => println!("Invalid record type provided"),
        // "qtype" was not provided, the rule for both types are deleted
        _ => {
            println!("Record type not provided, deleting rule for both v4 and v6");

            del_count += hdel(&mut connection, matchclass.clone(), "A")?;
            del_count += hdel(&mut connection, matchclass.clone(), "AAAA")?
        }
    }

    println!("{del_count} rules were deleted");

    Ok(ExitCode::SUCCESS)
}
