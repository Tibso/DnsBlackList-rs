use crate::VERSION;

use time::OffsetDateTime;
use redis::{aio::ConnectionManager, pipe, Pipeline, RedisError};
use tokio::time::{sleep, Duration};
use serde_json::{json, Value};
use serde::Deserialize;
use reqwest::{header::{ACCEPT, AUTHORIZATION, USER_AGENT}, Client, RequestBuilder};
use tracing::{error, info, warn};
use std::{collections::HashMap, error::Error};

#[derive(Deserialize, Debug)]
/// MISP Config
pub struct MispAPIConf {
    /// API url
    url: String,

    /// API token key
    token: String,

    /// Update frequency in seconds
    ///
    /// TODO: Might change this to minutes in the future to simplify configuration file
    update_freq_secs: u64,
    
    /// Max age of attributes fetched
    ///
    /// Example: "7d" will fetch all attributes that are LESS THAN a week old or EXACTLY a week old
    request_timestamp: String,

    /// Numbers of attributes fetched on one page
    ///
    /// Tip: Set this wisely to not nuke the MISP instance
    request_item_limit: i32,

    /// Retention time of the MISP records
    ///
    /// TODO: Might change this to minutes in the future to simplify configuration file
    retention_time_secs: i64
}

/// Simplified MISP Attribute Item
struct MispItem {
    typ: String,
    val: String
}

/// MISP update task - Adds records to DB
pub async fn update(
    misp_api_conf: MispAPIConf,
    mut redis_mngr: ConnectionManager
) {
    let client = Client::new();
    let MispAPIConf { update_freq_secs, request_item_limit, request_timestamp, .. } = misp_api_conf;

    let date: String = {
        let now = OffsetDateTime::now_utc();
        format!("{:4}-{:02}-{:02}-{:02}:{:02}",
            now.year(), now.month(), now.day(), now.hour(),now.minute())
    };
    let fields = [("enabled","1"),("date",&date),("src","misp")];

    let user_agent = format!("DnsBlackList-rs v{VERSION}");
    let request = client.post(misp_api_conf.url)
        .header(AUTHORIZATION, misp_api_conf.token)
        .header(ACCEPT, "application/json")
        .header(USER_AGENT, user_agent);
    let json_body = json!({
        "returnFormat":"json",
        "type":{"OR":["hostname","domain","domain|ip","ip-dst","ip-src"]},
        "enforceWarninglist":true,
        "to_ids":1,
        "timestamp":request_timestamp,
        "limit":request_item_limit
    });

    info!("MISP update task ready");

    loop {
        info!("MISP update task running...");

        let err_fmt = "Failed to update MISP records: ";

        let (mut hmset_acc, mut expire_acc, mut results_acc): (u64, u64, u64) = (0, 0, 0);
        let mut pipe = pipe();
        let mut request_page: i32 = 1;
        let mut last_item_cnt = request_item_limit;
        while last_item_cnt >= request_item_limit {
            let json = match query(&request, &json_body, request_page).await {
                Ok(json) => json,
                Err(e) => {
                    error!("{err_fmt}{e}");
                    break
                }
            };

            let Some(attributes) = json.get("response")
                .and_then(|r| r.get("Attribute"))
                .and_then(|a| a.as_array())
            else {
                error!("{err_fmt}Response JSON not formatted as expected");
                break
            };
            if attributes.is_empty() {
                info!("No new MISP records to add");
                break
            }

            // items should be limited to i32
            last_item_cnt = attributes.len() as i32;
            let items: Vec<MispItem> = attributes.iter()
                .filter_map(|i| {
                    let typ = i.get("type")?.as_str()?;
                    let val = i.get("value")?.as_str()?;
                    Some(MispItem {
                        typ: typ.to_string(),
                        val: val.to_string()
                    })
                })
                .fold(HashMap::new(), |mut acc, item| {
                    acc.entry(item.val.clone()).or_insert(item);
                    acc
                })
                .into_values()
                .collect();

            if let Err(e) = pipe_items(&mut pipe, items, &fields, misp_api_conf.retention_time_secs) {
                error!("{err_fmt}{e}");
                break
            }

            if ! pipe.is_empty() {
                match compute_pipe(&mut redis_mngr, &mut pipe).await {
                    Ok((hmset_tot, expire_tot, results_cnt)) => {
                        hmset_acc += hmset_tot;
                        expire_acc += expire_tot;
                        results_acc += results_cnt;

                        info!("Adding new MISP records... {hmset_acc}");
                    },
                    Err(e) => {
                        error!("{err_fmt}{e}");
                        request_page += 1;
                        continue
                    }
                }
                pipe.clear();
            }

            request_page += 1;
        }

        if hmset_acc > 0 {
            info!("A total of {hmset_acc} new MISP records were added");
            if hmset_acc != expire_acc {
                warn!("Not all records were properly added or their expiry could not be set");
            }
            if hmset_acc != results_acc {
                warn!("Maybe some records were already in DB");
            }
        }

        sleep(Duration::from_secs(update_freq_secs)).await;
 
        //let mut update_tries = 0u8;
        //loop {
        //    match pipe().query_async(redis_mngr).await {
        //        Ok(_) => break,
        //        Err(e) => {
        //            error!("{daemon_id}: Failed to send updated records to Redis: {e}");
        //            update_tries += 1;
        //            if update_tries >= 3 {
        //                error!("{daemon_id}: Update task could not update Redis");
        //                break
        //            }
        //
        //            info!("{daemon_id}: Update task will try to update Redis again in 1min");
        //            sleep(Duration::from_secs(60));
        //        }
        //    }
        //}
    }
}

/// Executes and formats the results of the Redis Pipeline
async fn compute_pipe(
    redis_mngr: &mut ConnectionManager,
    pipe: &mut Pipeline
) -> Result<(u64, u64, u64), RedisError> {
    let results = pipe.query_async::<Vec<(String, u8)>>(redis_mngr).await?;
    let results_cnt = results.len();
    
    let (hmset_tot, expire_tot) = results.into_iter()
        .fold((0u64, 0u64), |(h_acc, e_acc), (h, e)| {
            let h_val = if h.to_lowercase() == "ok" { 1 } else { 0 };
            (h_acc + h_val, e_acc + e as u64)
        });

    Ok((hmset_tot, expire_tot, results_cnt as u64))
}

/// Query MISP instance for new records
async fn query(
    request: &RequestBuilder,
    json_body: &Value,
    request_page: i32
) -> Result<Value, Box<dyn Error>> {
    // request is from memory and should always be cloneable
    let request = request.try_clone().unwrap();
    let mut json_body = json_body.clone();
    // adds the "page" property that increments each loop
    json_body["page"] = json!(request_page);
    let request = request.json(&json_body);
    let response = request.send().await?;
    Ok(response.json::<Value>().await?)
}

/// Pipe MISP items in Redis Pipeline 
fn pipe_items(
    pipe: &mut Pipeline,
    items: Vec<MispItem>,
    fields: &[(&str,&str); 3],
    secs_3months: i64
) -> Result<(), Box<dyn Error>> {
    for item in items {
        match item.typ.as_str() {
            "domain|ip" => {
                let (domain, ip) = item.val.split_once('|').unwrap();
                let domain_key = format!("DBL;D;malware;{domain}");
                let ip_key = format!("DBL;I;malware;{ip}");

                pipe
                    .hset_multiple(&domain_key, fields)
                    .expire(domain_key, secs_3months);
                pipe
                    .hset_multiple(&ip_key, fields)
                    .expire(ip_key, secs_3months);
            },
            "domain" | "hostname" => {
                let domain = item.val;
                let domain_key = format!("DBL;D;malware;{domain}");
                
                pipe
                    .hset_multiple(&domain_key, fields)
                    .expire(domain_key, secs_3months);
            },
            "ip-src" | "ip-dst" => {
                let ip = item.val;
                let ip_key = format!("DBL;I;malware;{ip}");

                pipe
                    .hset_multiple(&ip_key, fields)
                    .expire(ip_key, secs_3months);
            },
            _ => return Err(format!("Unexpected attribute type: {}", item.typ).into())
        }
    }
    Ok(())
}
