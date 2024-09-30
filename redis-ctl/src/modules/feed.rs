use crate::modules::get_datetime;

use std::{
    fs::{self, File},
    path::PathBuf, process::ExitCode, collections::HashSet, net::IpAddr,
    io::{BufReader, BufRead}
};
use serde::Deserialize;
use reqwest;
use redis::{cmd, Commands, Connection, RedisResult};

struct Source {
    name: String,
    filters: Vec<Filter>
}
struct Filter {
    name: String,
    domains: Vec<String>
}

#[derive(Deserialize)]
struct SourcesLists {
    name: String,
    lists: Vec<List>
}
#[derive(Deserialize)]
struct List {
    filter: String,
    urls: Vec<String>
}

/// Automatically updates the rules using the "dnsblrs_sources.json" file
/// in a non-blocking fashion
pub fn auto (
    connection: &mut Connection,
    path_to_srcs: &PathBuf
) -> RedisResult<ExitCode> {
    let data = match fs::read_to_string(path_to_srcs) {
        Ok(data) => data,
        Err(err) => {
            println!("Error reading \"dnsblrs_sources.json\": {err}");
            // ExitCode EX_NOINPUT
            return Ok(ExitCode::from(66))
        }
    };

    let srcs_list: Vec<SourcesLists> = match serde_json::from_str(&data) {
        Ok(srcs_list) => srcs_list,
        Err(err) => {
            println!("Error deserializing \"dnsblrs_sources.json\" data: {err}");
            // ExitCode EX_DATAERR
            return Ok(ExitCode::from(65))
        }
    };

    let client = reqwest::blocking::Client::new();

    println!("Downloading and encoding files...");
    let mut dl_cnt = 0usize;
    
    let mut srcs: Vec<Source> = vec![];
    for src in srcs_list {
        let mut filters: Vec<Filter> = vec![];
        for list in src.lists {
            let mut domains: Vec<String> = vec![];
            for url in list.urls {
                let resp = match client.get(&url).send() {
                    Ok(resp) => resp,
                    Err(err) => {
                        println!("Error retrieving data from \"{url}\":\n{err}\nSkipping...");
                        continue
                    }
                };
                
                if ! resp.status().is_success() {
                    println!("Error requesting for \"{url}\":\n{}\nSkipping...", resp.status());
                    continue
                }
        
                let text: String = match resp.text() {
                    Ok(text) => text,
                    Err(err) => {
                        println!("Error encoding bytes to UTF-8: {err}\nSkipping...");
                        continue
                    }
                };

                dl_cnt += 1;

                for line in text.lines() {
                    if line.is_empty() {
                        continue
                    }

                    if line.trim().starts_with('#') {
                        continue
                    }
                    
                    // Input file could be formatted like "hosts.txt"
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    match parts.len() {
                        1 => domains.push(parts[0].to_owned()),
                        2 => domains.push(parts[1].to_owned()),
                        _ => continue
                    };
                }
            }
            filters.push(Filter {
                name: list.filter,
                domains
            });
        }
        srcs.push(Source {
            name: src.name,
            filters
        });
    }

    println!("{dl_cnt} file(s) downloaded and encoded");

    if srcs.is_empty() {
        println!("No data was retrieved");
        // ExitCode EX_IOERR
        return Ok(ExitCode::from(74))
    }

    println!("Querying Redis...");

    let mut found_cnt = 0usize;
    let mut cursor = 0u32;
    loop {
        let scan_keys: Vec<String>;
        (cursor, scan_keys) = cmd("scan").arg(cursor)
            .arg("count").arg(10000)
            .arg("match").arg("DBL;R;*")
            .query(connection)?;

        if scan_keys.is_empty() {
            if cursor == 0 {
                break
            }
            continue
        }

        let mut keys_set: HashSet<String> = HashSet::new();
        for key in scan_keys {
            keys_set.insert(key);
        }
        for src in &mut srcs {
            for filter in &mut src.filters {
                let hkey_prefix = format!("DBL;R;{};", filter.name);
                filter.domains.retain(|domain| {
                    let hkey = hkey_prefix.clone() + domain;
                    if keys_set.contains(&hkey) {
                        found_cnt += 1;
                        false
                    } else {
                        true
                    }
                });
            }
        }

        if cursor == 0 {
            break
        }
    }

    println!("{found_cnt} rule(s) already found on Redis");
    println!("Adding new rules to Redis...");

    let (year, month, day) = get_datetime::get_datetime();

    let mut add_cnt = 0usize;
    for src in &srcs {
        for filter in &src.filters {
            let hkey_prefix: String = format!("DBL;R;{};", filter.name.as_str());
            for domain in &filter.domains {
                let hkey = hkey_prefix.clone() + domain;

                if let Ok(res) = connection.hset_multiple(hkey.clone(), &[
                    ("A", "1"), ("AAAA", "1"),
                    ("enabled", "1"),
                    ("date", format!("{year}{month}{day}").as_str()),
                    ("source", src.name.as_str())
                ]) {
                    if res {
                        add_cnt += 1;
                    }
                }
            }
        }
    }

    println!("{add_cnt} rule(s) added to Redis");

    Ok(ExitCode::SUCCESS)
}

/// Feeds a list of domains to a filter
pub fn add_to_filter (
    connection: &mut Connection,
    path_to_list: &PathBuf,
    filter: &str,
    src: &str
) -> RedisResult<ExitCode> {
    let file = File::open(path_to_list)?;

    let (year, month, day) = get_datetime::get_datetime();
    let date = format!("{year}{month}{day}");
    let date = date.as_str();

    // If no filter is given, will assume a backup is being fed

    let mut add_cnt = 0usize;
    let mut line_cnt = 0usize;
    // Initializes a buffered reader and stores an iterator of its lines
    // This reader reads the file dynamically by reading big chunks of the file
    let lines = BufReader::new(file).lines();
    for line in lines {
        line_cnt += 1;

        if let Ok(line) = line {
            let mut split = line.split_ascii_whitespace();

            let Some(domain_name) = split.next() else {
                continue
            };

            let mut args: Vec<String> = vec![
                "enabled".to_string(), "1".to_string(),
                "date".to_string(), date.to_string(), 
                "source".to_string(), src.to_string()];

            // Variable that stores whether or not the both v4 and v6 rules should be set to default
            let mut are_both_default = true;

            for ip in split {
                are_both_default = false;

                match ip {
                    "A" => args.extend(["A".to_string(), "1".to_string()]),
                    "AAAA" => args.extend(["AAAA".to_string(), "1".to_string()]),
                    _ => {
                        let Ok(ip) = ip.parse::<IpAddr>() else {
                            println!("Error parsing line: {line_cnt}!");
                            continue
                        };
                        if ip.is_ipv4() {
                            args.extend(["A".to_string(), ip.to_string()])
                        } else {
                            args.extend(["AAAA".to_string(), ip.to_string()])
                        }
                    }
                }
            }

            // If no default or IP was provided, both IPs are set as default
            if are_both_default {
                args.extend(["A".to_string(), "1".to_string(),
                "AAAA".to_string(), "1".to_string()]);
            }

            // cmd is used because .hset_multiple doesn't take a Vec<(&str, &str)>
            match cmd("hset").arg(format!("DBL;R;{filter};{domain_name}"))
                .arg(args).query(connection) {
                Ok(res) => if res {
                    add_cnt += 1;
                },
                Err(err) => println!("Error feeding filter on line {line_cnt}:\nERR: {err}")
            }
        }
    }

    println!("{add_cnt} rule(s) added to Redis");

    Ok(ExitCode::SUCCESS)
}
