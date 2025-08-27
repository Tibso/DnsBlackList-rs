pub mod rules;
pub mod stats;

use time::OffsetDateTime;

fn get_date() -> String {
    let now = OffsetDateTime::now_utc();
    format!("{:4}-{:02}-{:02}-{:02}:{:02}",
        now.year(), now.month(), now.day(), now.hour(), now.minute())
}

/// calculate future epoch from time abbreviation
fn time_abrv_to_secs(time_abrv: &str) -> Option<i64> {
    if time_abrv.len() != 2 {
        return None
    }

    let (num_str, unit) = time_abrv.split_at(1);
    let Ok(num) = num_str.parse::<u64>() else {
        return None
    };
    
    if unit.len() != 1 {
        return None
    }
    let secs = match unit.as_bytes()[0] as char {
        's' => num,
        'm' => num * 60,
        'h' => num * 3600,
        'd' => num * 86400,
        'w' => num * 604800,
        'M' => num * 2678400,
        'y' => num * 31536000,
        _ => return None
    };

    let Ok(secs) = i64::try_from(secs) else {
        return None
    };

    Some(secs)
}

fn is_valid_domain(domain: &str) -> bool {
    if domain.len() > 253 {
        return false
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false
    }

    if let Some(tld) = labels.last() {
        if tld.len() < 2 {
            return false
        }
    }

    if labels.iter().any(|label|
        label.is_empty() || 
        label.len() > 63 || 
        label.starts_with('-') || 
        label.ends_with('-')
    ) {
        return false
    } 

    true
}

