/*
use redis::{RedisResult, Connection};

use std::{io::Write, fs, process::ExitCode, path::Path};

use crate::{redis_mod, modules::get_datetime};

/// Makes a full backup
/// 
/// If the full backup file already exists, it will be overwritten
/// Note that the date is appended to the end of file name
pub fn create_full (
    mut connection: Connection,
    path_to_backup: &str
)
-> RedisResult<ExitCode> {
    println!("Creating the full backup directory...");

    let new_dir_string = format!("{path_to_backup}/bkp");
    let path_new_dir = Path::new(&new_dir_string);
    if ! path_new_dir.exists() {
        if let Err(err) = fs::create_dir_all(path_new_dir) {
            println!("Error creating new directories: {new_dir_string}\nERR: {err}!");
            // ExitCode EX_CANTCREATE
            return Ok(ExitCode::from(73))
        }
    }
    let bkp_path_string = {
        let (year, month, day) = get_datetime::get_datetime();
        format!("{new_dir_string}/full-{year}{month}{day}")
    };
    let bkp_path = Path::new(&bkp_path_string);
    let Ok(mut bkpfile) = fs::OpenOptions::new().write(true).create(true).open(bkp_path) else {
        println!("Error creating/opening the backup file!");
        return Ok(ExitCode::from(73))
    };

    let mut bkp_add_count = 0u32;
    let mut key_count = 0u32;
    let mut cursor = 0u32;
    loop {
        let keys: Vec<String>;
        (cursor, keys) = redis_mod::scan(&mut connection, cursor, "DBL*")?;
        if keys.is_empty() {
            if cursor == 0 {
                break
            }
            continue
        }

        for key in keys {
            key_count += 1;

            let Ok(key_type) = redis_mod::get_type(&mut connection, &key) else {
                continue
            };

            let line: String;
            match key_type.as_str() {
                "hash" => {
                    let Ok(hash) = redis_mod::fetch(&mut connection, "hgetall", &vec![key.clone()]) else {
                        continue
                    };
                    line = format!("hset {key} {}", hash.join(" "));
                },
                "set" => {
                    let Ok(set) = redis_mod::fetch(&mut connection, "smembers", &vec![key.clone()]) else {
                        continue
                    };
                    line = format!("sadd {key} {}", set.join(" "));
                },
                _ => {
                    println!("Error: Key: \"{key}\" is of the unexpected type: \"{key_type}\"!");
                    continue
                }
            }
            if writeln!(bkpfile, "{line}").is_ok() {
                bkp_add_count += 1;
            }
        }

        if cursor == 0 {
            break
        }
    }

    if bkp_add_count == key_count {
        println!("Full backup successfull.");
    } else if bkp_add_count < key_count {
        println!("{bkp_add_count}/{key_count} items were backed up.");
    } else if bkp_add_count == 0 {
        println!("Error: Full backup failed! No items were backed up!");
        // EX_UNAVAILABLE exitcode
        return Ok(ExitCode::from(69))
    } else {
        println!("Error: {bkp_add_count} items were backed up out of {key_count} items that were iterated over!");
        // EX_SOFTWARE exitcode
        return Ok(ExitCode::from(70))
    }

    Ok(ExitCode::SUCCESS)
}

pub fn create_incr (

)
-> RedisResult<ExitCode> {


    Ok(ExitCode::SUCCESS)
}

pub fn load_full (

)
-> RedisResult<ExitCode> {


    Ok(ExitCode::SUCCESS)
}

pub fn load_incr (

)
-> RedisResult<ExitCode> {


    Ok(ExitCode::SUCCESS)
}
*/