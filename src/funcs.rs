use aws_config::BehaviorVersion;
use aws_sdk_cloudwatchlogs::operation::filter_log_events::builders::FilterLogEventsFluentBuilder;
use aws_sdk_cloudwatchlogs::Client;
use chrono::Duration as Delta;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use console::Style;
use log::info;
use std::convert::From;
use std::result::Result;
use std::time::Duration;
use serde_json::Value;

pub enum AWSResponse {
    Token(String),
    LastLog(Option<i64>),
}

fn calculate_start_time(from: DateTime<Local>, delta: Duration) -> Option<i64> {
    let chrono_delta = Delta::from_std(delta).unwrap();
    let start_time = from.checked_sub_signed(chrono_delta).unwrap();
    // Amazon uses time in UTC so we have to convert
    let utc_time = DateTime::<Utc>::from_utc(start_time.naive_utc(), Utc);
    return Some(utc_time.timestamp_millis());
}

pub fn create_filter_request(
    cl: &Client,
    group: &String,
    start: Duration,
    filter: Option<String>,
    token: Option<String>,
) -> FilterLogEventsFluentBuilder {
    let delta = calculate_start_time(Local::now(), start);
    cl.filter_log_events()
    .set_start_time(delta)
    .set_next_token(token)
    .set_limit(Some(100))
    .set_filter_pattern( filter)
    .log_group_name(group.to_string())
}

pub fn create_filter_from_timestamp(
    cl: &Client,
    group: &String,
    start: Option<i64>,
    filter: Option<String>,
    token: Option<String>,
) -> FilterLogEventsFluentBuilder {
    cl.filter_log_events()
    .set_start_time ( start)
    .set_next_token ( token)
    .set_limit ( Some(100))
    .set_filter_pattern ( filter)
    .log_group_name ( group.to_string())
}

fn print_date(time: Option<i64>) -> String {
    match time {
        //TODO: WTF!!
        Some(x) => DateTime::<Local>::from(DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(x / 1000, 0),
            Utc,
        ))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string(),
        None => "".to_owned(),
    }
}

pub async fn fetch_logs(
    _client: &Client,
    last_time: &mut Option<i64>,
    req: FilterLogEventsFluentBuilder,
    timeout: Duration,
    json_mode: bool,
) -> Result<AWSResponse, anyhow::Error> {
    info!("Sending log request {:?}", &req);
    let start_time = req.get_start_time().clone();
    match tokio::time::timeout(timeout, req.send()).await? {
        Ok(response) => {
            info!("Got response {:?}", &response);
            let mut events = response.events.unwrap();
            let green = Style::new().green();
            events.sort_by_key(|x| x.timestamp.map_or(-1, |x| x));
            for event in &events {
                let message = event.message.as_ref().map_or("".into(), |x| x.clone());
                if json_mode {
                    if let Ok(line) = json_msg_with_timestamp(&message, event.timestamp) {
                        println!("{}", line);
                        continue;
                    }
                }; 
                println!("{} {}",
                    green.apply_to(print_date(event.timestamp)),
                    message,
                );
            }
            let last_evt_opt = events.last();
            if let Some(last_evt) = last_evt_opt {
                *last_time = last_evt.timestamp;
            }
            match response.next_token {
                Some(x) => Ok(AWSResponse::Token(x)),
                _ => Ok(AWSResponse::LastLog(last_time.map_or(start_time, |i| Some(i))))

            }
        }
        Err(x) => return Err(anyhow::anyhow!(x)),
    }
}

fn json_msg_with_timestamp(msg: &str, timestamp: Option<i64>) -> anyhow::Result<String> {
    let mut value = serde_json::from_str::<Value>(msg)?;
    let map = value.as_object_mut().ok_or(anyhow::anyhow!("oh no obj"))?;
    map.insert(
        "@timestamp".to_owned(),
        serde_json::to_value(print_date(timestamp))?,
    );
    map.retain(|_, v| v.is_null() == false);

    Ok(serde_json::to_string(&value)?)
}

pub async fn client_with_profile(name: &str, region: aws_config::Region, role_arn: Option<String>) -> Client {
    let mut config_loader = aws_config::defaults(BehaviorVersion::v2023_11_09())
        .profile_name(name)
        .region(region);
    
    if let Some(role) = role_arn {
        let sts_config = aws_config::defaults(BehaviorVersion::v2023_11_09())
            .profile_name(name)
            .region(region.clone())
            .load()
            .await;
        let sts_client = aws_sdk_sts::Client::new(&sts_config);
        
        let provider = aws_config::sts::AssumeRoleProvider::builder(role)
            .session_name("awstail")
            .build_from_provider(sts_client)
            .await;
        
        config_loader = config_loader.credentials_provider(provider);
    }
    
    let cfg = config_loader.load().await;
    aws_sdk_cloudwatchlogs::Client::new(&cfg)
}

pub async fn list_log_groups(c: &Client) -> Result<(), anyhow::Error> {
    let mut req = c.describe_log_groups();
    loop {
        info!("Sending list log groups request {:?}", &req);
        let resp = req.send().await?;
        match resp.log_groups {
            Some(x) => {
                for group in x {
                    println!("{}", group.log_group_name.unwrap())
                }
            }
            None => break,
        }
        match resp.next_token {
            Some(x) => {
                req = c.describe_log_groups()
                .next_token(x)
            }
            None => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Local};
    use humantime::parse_duration;

    #[test]
    fn test_calculate_start_time() {
        let local = Local::now();
        let duration = parse_duration("1d").unwrap();
        assert_eq!(
            calculate_start_time(local, duration).unwrap(),
            (local - Duration::days(1)).timestamp_millis()
        )
    }
}
