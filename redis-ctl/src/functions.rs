use crate::{Confile, redis_mod::{get_elements, del_vec, hset, hdel, sadd_vec, del, sadd}};

use std::{
    path::PathBuf, fs::File, net::IpAddr, process::ExitCode,
    io::{BufReader, BufRead}
};
use redis::{Connection, RedisResult};

/// Displays the daemon's configuration
pub fn show_conf (
    mut connection: Connection,
    confile: Confile
)
-> RedisResult<ExitCode> {
    // Retrives the daemon's configuration as the server would when starting
    println!("{confile:#?}");

    let binds = get_elements(&mut connection, "smembers", format!("dnsblrsd:binds:{}", confile.daemon_id))?;
    match binds.is_empty() {
        true => println!("No bind is configured"),
        false => println!("binds {binds:#?}")
    }

    let forwarders = get_elements(&mut connection, "smembers", format!("dnsblrsd:forwarders:{}", confile.daemon_id))?;
    match forwarders.is_empty() {
        true => println!("No forwarder is configured"),
        false => println!("forwarders {forwarders:#?}")
    }

    let matchclasses = get_elements(&mut connection, "smembers", format!("dnsblrsd:matchclasses:{}", confile.daemon_id))?;
    match matchclasses.is_empty() {
        true => println!("No matchclass is configured"),
        false => println!("matchclasses {matchclasses:#?}")
    }

    let blackhole_ips = get_elements(&mut connection, "smembers", format!("dnsblrsd:blackhole_ips:{}", confile.daemon_id))?;
    match blackhole_ips.is_empty() {
        true => println!("No blackhole IP is configured"),
        false => println!("blackhole_ips {blackhole_ips:#?}")
    }

    Ok(ExitCode::SUCCESS)
}

/// Deletes all stats that match an IP pattern
pub fn clear_stats (
    mut connection: Connection,
    daemon_id: String,
    pattern: String
)
-> RedisResult<ExitCode> {
    // Fetches all stats that match "daemon_id" and "pattern"
    let hashes = get_elements(&mut connection, "keys", format!("dnsblrsd:stats:{daemon_id}:{pattern}"))?;

    // Deletes all stats found
    let del_count = del_vec(&mut connection, hashes)?;

    println!("{del_count} stats were deleted");

    Ok(ExitCode::SUCCESS)
}

/// Displays all stats that match an IP pattern
pub fn get_stats (
    mut connection: Connection,
    daemon_id: String,
    pattern: String
)
-> RedisResult<ExitCode> {
    // Fetches all stats that match "daemon_id" and "pattern"
    let hashes = get_elements(&mut connection, "keys", format!("dnsblrsd:stats:{daemon_id}:{pattern}"))?;

    // Fetches all the values of each hash
    for hash in hashes {
        let values = get_elements(&mut connection, "hgetall", hash.clone())?;

        let split: Vec<&str> = hash.split(':').collect();

        print!("Stats for hash: \"{}\":\n{:#?}\n", split[2], values)
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
    let fields = get_elements(&mut connection, "hgetall", matchclass)?;

    match fields.is_empty() {
        true => {
            println!("The matchclass doesn't exist or doesn't have any field");
            return Ok(ExitCode::from(1))
        },
        false => println!("{fields:#?}")
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
    let hashes = get_elements(&mut connection, "keys", pattern)?;

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
            let mut are_both_default = true;

            // If an additionnal value was given to the command
            if let Some(ip_1) = split.next() {
                // The default values should not be used
                are_both_default = false;

                // Tries to parse it to an IP address
                match ip_1.parse::<IpAddr>() {
                    // If the parsing was successful, value is an IP and is not the default value
                    Ok(ip) => match ip.is_ipv4() {
                        // If the IP is v4, set the approriate rule
                        true => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", ip_1.to_string()) {
                            // If the command was successful, we add the number of rules set by the command to the counter
                            Ok(_) => add_count += 1,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        // If not v4 then v6
                        false => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", ip_1.to_string()) {
                            Ok(_) => add_count += 1,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        }
                    },
                    // If the parsing failed, the value should be a default value
                    Err(_) => match ip_1 {
                        // If the value is the default for v4
                        "A" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", "1".to_string()) {
                            Ok(_) => add_count += 1,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        // If not default v4 then v6
                        "AAAA" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", "1".to_string()) {
                            Ok(_) => add_count += 1,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_1}\" on line: {line_count}")
                        },
                        // Couldn't parse the value
                        _ => println!("Error parsing {ip_1} item on line: {line_count}")
                    }
                };
            }

            // Ditto as first value, but tries to parse v6 first as user would most likely input v6 after v4
            if let Some(ip_2) = split.next() {
                are_both_default = false;

                match ip_2.parse::<IpAddr>() {
                    Ok(ip) => match ip.is_ipv6() {
                        true => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", ip_2.to_string()) {
                            Ok(_) => add_count += 1,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_2}\" on line: {line_count}")
                        },
                        false => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", ip_2.to_string()) {
                            Ok(_) => add_count += 1,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_2}\" on line: {line_count}")
                        }
                    },
                    Err(_) => match ip_2 {
                        "AAAA" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", "1".to_string()) {
                            Ok(_) => add_count += 1,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_2}\" on line: {line_count}")
                        },
                        "A" => match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", "1".to_string()) {
                            Ok(_) => add_count += 1,
                            Err(_) => println!("Error feeding matchclass with: \"{ip_2}\" on line: {line_count}")
                        },
                        _ => println!("Error parsing {ip_2} item on line: {line_count}")
                    }
                }
            }

            // If at least 1 default or IP wasn't provided, both IPs are set as default
            if are_both_default {
                match hset(&mut connection, format!("{matchclass}:{domain_name}"), "A", "1".to_string()) {
                    Ok(_) => add_count += 1,
                    Err(_) => println!("Error feeding matchclass with default A on line: {line_count}")
                }
                match hset(&mut connection, format!("{matchclass}:{domain_name}"), "AAAA", "1".to_string()) {
                    Ok(_) => add_count += 1,
                    Err(_) => println!("Error feeding matchclass with default AAAA on line: {line_count}")
                }
            }
        }
    }

    println!("{add_count} lines out of {line_count} parsed lines were fed");

    Ok(ExitCode::SUCCESS)
}

/// Adds a new rule
pub fn set_rule (
    mut connection: Connection,
    rule: String,
    qtype: Option<String>,
    ip: Option<String>
)
-> RedisResult<ExitCode> {
    let mut add_count = 0u8;

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
                            // ExitCode "2" is used to indicate syntax issue
                            return Ok(ExitCode::from(2))
                        }
                    };

                    // Provided "ip" must be v4
                    if ip.is_ipv4() {
                        if hset(&mut connection, rule, "A", ip.to_string())? {
                            add_count += 1
                        }
                    } else {
                        println!("Provided IP was not v4")
                    }
                },
                // If "ip" value not provided, sets a default rule for v4
                None => if hset(&mut connection, rule, "A", "1".to_string())? {
                    add_count += 1
                }
            }
        },
        // If "qtype" specifies v6
        Some("AAAA") => {
            match ip {
                Some(_) => {
                    let ip = match ip.unwrap().parse::<IpAddr>() {
                        Ok(ok) => ok,
                        Err(err) => {
                            println!("Error parsing IpAddr: {:?}", err);
                            return Ok(ExitCode::from(2))
                        }
                    };

                    // Provided "ip" must be v6
                    if ip.is_ipv6() {
                        if hset(&mut connection, rule, "AAAA", ip.to_string())? {
                            add_count += 1
                        }
                    } else {
                        println!("Provided IP was not v6")
                    }
                },
                // If "ip" value not provided, sets a default rule for v6
                None => if hset(&mut connection, rule, "AAAA", "1".to_string())? {
                    add_count += 1
                }
            }
        },
        // Provided "qtype" was not "A" or "AAAA" so it is incorrect
        Some(_) => println!("Invalid record type was provided"),
        // "qtype" was not provided, the default rules are added for both types
        None => {
            println!("Record type not provided, adding default rule for both v4 and v6");

            if hset(&mut connection, rule.clone(), "A", "1".to_string())? {
                add_count += 1
            }
            if hset(&mut connection, rule, "AAAA", "1".to_string())? {
                add_count += 1
            }
        }
    }

    match add_count {
        2 => println!("Both rules were successfully added"),
        1 => println!("1 rule was successfully added"),
        0 => {
            println!("The rule(s) already exist");
            // ExitCode "1" is used to indicate a general error
            return Ok(ExitCode::from(1))
        },
        _ => unreachable!()
    }

    Ok(ExitCode::SUCCESS)
}

/// Deletes a rule
pub fn delete_rule (
    mut connection: Connection,
    rule: String,
    qtype: Option<String>
)
-> RedisResult<ExitCode> {
    let mut result = false;

    // Checks if "qtype" is provided, if it is, tries to delete the approriate rule
    match qtype.as_deref() {
        // If "qtype" specifies v4
        Some("A") => result = hdel(&mut connection, rule, "A")?,
        // If "qtype" specifies v6
        Some("AAAA") => result = hdel(&mut connection, rule, "AAAA")?,
        Some(_) => println!("Invalid record type provided"),
        // "qtype" was not provided, the rule for both types are deleted
        _ => {
            println!("Record type not provided, deleting rule for both v4 and v6");

            result = del(&mut connection, rule)?
        }
    }

    match result {
        true => println!("The rule was successfully deleted"),
        false => {
            println!("The rule does not exist");
            return Ok(ExitCode::from(1))
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Adds binds to the dnsblrsd's configuration
pub fn add_binds (
    mut connection: Connection,
    daemon_id: String,
    binds: Vec<String>
)
-> RedisResult<ExitCode> {
    if binds.is_empty() {
        println!("No binds was provided");
        return Ok(ExitCode::from(2))
    }

    let add_count = sadd_vec(&mut connection, format!("dnsblrsd:binds:{daemon_id}"), binds)?;

    println!("{add_count} binds were added to the configuration");

    Ok(ExitCode::SUCCESS)
}

/// Clear a parameter from the dnsblrsd's configuration
pub fn clear_parameter (
    mut connection: Connection,
    daemon_id: String,
    parameter: String
)
-> RedisResult<ExitCode> {
    let del_count = del(&mut connection, format!("dnsblrsd:{parameter}:{daemon_id}"))?;

    match del_count {
        true => println!("The parameter was successfully deleted"),
        false => {
            println!("The parameter does not exist");
            return Ok(ExitCode::from(1))
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Reconfigures the forwarders of the dnsblrsd's configuration
pub fn set_forwarders (
    mut connection: Connection,
    daemon_id: String,
    forwarders: Vec<String>
)
-> RedisResult<ExitCode> {
    // Only 2 forwarders can be set
    if forwarders.len() == 2 {
        del(&mut connection, format!("dnsblrsd:forwarders:{daemon_id}"))?;

        let add_count = sadd_vec(&mut connection, format!("dnsblrsd:forwarders:{daemon_id}"), forwarders)?;
    
        println!("{add_count} forwarders were added to the configuration")
    } else {
        println!("2 forwarders must be provided");
        return Ok(ExitCode::from(2))
    }

    Ok(ExitCode::SUCCESS)
}

/// Reconfigures the "blackhole_ips" of the dnsblrsd's configuration
pub fn set_blackhole_ips (
    mut connection: Connection,
    daemon_id: String,
    blackhole_ips: Vec<String>
)
-> RedisResult<ExitCode> {
    // Only 2 blackhole_ips can be set
    if blackhole_ips.len() == 2 {
        del(&mut connection, format!("dnsblrsd:blackhole_ips:{daemon_id}"))?;

        let add_count = sadd_vec(&mut connection, format!("dnsblrsd:blackhole_ips:{daemon_id}"), blackhole_ips)?;

        println!("{add_count} blackhole_ips were added to the configuration");
    } else {
        println!("2 blackhole_ips must be provided");
        return Ok(ExitCode::from(2))
    }

    Ok(ExitCode::SUCCESS)
}

/// Adds blocked IPs to the dnsblrsd's configuration
pub fn add_blocked_ips (
    mut connection: Connection,
    daemon_id: String,
    to_blocked_ips: Vec<String>
)
-> RedisResult<ExitCode> {
    if to_blocked_ips.is_empty() {
        println!("No IP was provided");
        return Ok(ExitCode::from(2))
    }

    let mut add_count = 0usize;

    for to_blocked_ip in to_blocked_ips {
        // Each provided IP is parsed
        if let Ok(ip) = to_blocked_ip.parse::<IpAddr>() {
            // Each IP is stored in its respective blocklist
            if ip.is_ipv4() {
                if sadd(&mut connection, format!("dnsblrsd:blocked_ips_v4:{daemon_id}"), ip.to_string())? {
                    add_count += 1
                }
            } else if sadd(&mut connection, format!("dnsblrsd:blocked_ips_v6:{daemon_id}"), ip.to_string())? {
                add_count += 1
            }
        } else {
            println!("Error parsing IP: \"{to_blocked_ip}\"");
            return Ok(ExitCode::from(2))
        }
    }

    println!("{add_count} IPs were added to the IP blacklist");

    Ok(ExitCode::SUCCESS)
}
