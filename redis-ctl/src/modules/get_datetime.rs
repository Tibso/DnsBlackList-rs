use chrono::{Utc, Datelike, DateTime};

/// Get the date from chrono crate
pub fn get_datetime ()
-> (String, String, String) {
    let date_time: DateTime<Utc> = Utc::now();

    let year = format!("{:4}", date_time.year());
    let month = format!("{:02}", date_time.month());
    let day = format!("{:02}", date_time.day());

    (year, month, day)
}
