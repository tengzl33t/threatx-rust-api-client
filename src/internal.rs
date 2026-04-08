/*
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.

SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright tengzl33t

Author: tengzl33t
*/
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{body::Buf, Method, Request};
use hyper_util::rt::TokioExecutor;

use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::task::JoinSet;

#[allow(dead_code)]
#[derive(Debug)]
enum RequestError {
    TokenExpired,
    IncorrectState,
    ResponseError(Value),
    ProcessingError(Value),
}

pub(crate) static ENDPOINT_MAP: LazyLock<HashMap<&str, (u8, Vec<&str>)>> = LazyLock::new(|| {
    HashMap::from_iter([
        ("apikeys", (2, vec!["list", "new", "update", "revoke"])),
        ("apischemas", (1, vec!["save", "list", "delete"])),
        (
            "customers",
            (
                1,
                vec![
                    "list",
                    "list_all",
                    "new",
                    "get",
                    "update",
                    "delete",
                    "list_api_keys",
                    "new_api_key",
                    "delete_api_key",
                    "get_customer_config",
                    "set_customer_config",
                ],
            ),
        ),
        ("users", (1, vec!["list", "new", "get", "update", "delete"])),
        (
            "sites",
            (2, vec!["list", "new", "get", "delete", "update", "unset"]),
        ),
        ("sitegroups", (1, vec!["list", "save", "delete"])),
        ("templates", (1, vec!["set", "get", "delete"])),
        ("sensors", (1, vec!["list", "tags"])),
        ("services", (1, vec!["list"])),
        (
            "entities",
            (
                1,
                vec![
                    "list",
                    "show",
                    "state_changes",
                    "risk_changes",
                    "notes",
                    "new_note",
                    "reset",
                    "block_entity",
                    "blacklist_entity",
                    "whitelist_entity",
                    "watch_entity",
                    "list_most_risky",
                    "count",
                ],
            ),
        ),
        (
            "metrics",
            (
                1,
                vec![
                    "request_stats_by_hour",
                    "request_stats_by_minute",
                    "match_stats_by_hour",
                    "block_stats_by_endpoint",
                    "entity_stats_by_entity_by_quarter_hour",
                    "rules_matched_by_ip_by_quarter_hour",
                    "request_stats_by_endpoint",
                    "threat_stats_by_endpoint",
                    "threat_stats_by_hour",
                    "threat_stats_by_quarter_hour",
                    "threat_stats_by_site",
                    "status_codes_by_site",
                    "request_stats_hourly_by_site",
                    "request_stats_hourly_by_endpoint",
                ],
            ),
        ),
        (
            "subscriptions",
            (1, vec!["save", "delete", "list", "enable", "disable"]),
        ),
        ("globaltags", (1, vec!["new", "list"])),
        ("actortags", (1, vec!["new", "list", "delete"])),
        ("features", (1, vec!["list", "query", "save", "delete"])),
        ("channels", (1, vec!["new", "list", "update"])),
        ("globalsettings", (1, vec!["get"])),
        ("dnsinfo", (1, vec!["list"])),
        (
            "logs",
            (
                1,
                vec![
                    "events",
                    "entities",
                    "blocks",
                    "actions",
                    "matches",
                    "rule_hits",
                    "sysinfo",
                    "audit_log",
                ],
            ),
        ),
        (
            "logsv2",
            (2, vec!["block_events", "match_events", "audit_events"]),
        ),
        (
            "lists",
            (
                1,
                vec![
                    "list_blacklist",
                    "list_blocklist",
                    "list_whitelist",
                    "list_ignorelist",
                    "new_blacklist",
                    "new_blocklist",
                    "new_whitelist",
                    "new_ignorelist",
                    "bulk_new_blacklist",
                    "bulk_new_blocklist",
                    "bulk_new_whitelist",
                    "bulk_new_ignorelist",
                    "get_blacklist",
                    "get_blocklist",
                    "get_whitelist",
                    "get_ignorelist",
                    "delete_blacklist",
                    "delete_blocklist",
                    "delete_whitelist",
                    "delete_ignorelist",
                    "bulk_delete_blacklist",
                    "bulk_delete_blocklist",
                    "bulk_delete_whitelist",
                    "bulk_delete_ignorelist",
                    "ip_to_link",
                ],
            ),
        ),
        (
            "rules",
            (
                1,
                vec![
                    "list_customer_rules",
                    "list_whitelist_rules",
                    "list_profiler_rules",
                    "list_common_rules",
                    "new_customer_rule",
                    "new_whitelist_rule",
                    "new_common_rule",
                    "update_customer_rule",
                    "update_whitelist_rule",
                    "update_profiler_rule",
                    "update_common_rule",
                    "get_customer_rule",
                    "get_whitelist_rule",
                    "get_profiler_rule",
                    "get_common_rule",
                    "delete_customer_rule",
                    "delete_whitelist_rule",
                    "delete_profiler_rule",
                    "delete_common_rule",
                    "validate_rule",
                ],
            ),
        ),
    ])
});

fn get_header() -> String {
    format!("ThreatX-Rust-API-Client/{}", env!("CARGO_PKG_VERSION"))
}

pub(crate) fn get_api_host_part(api_env: &str) -> Result<String, String> {
    if api_env.is_empty() {
        return Err("Incorrect API environment provided".to_string());
    }

    let domain_part = "threatx.io".to_string();

    let subdomain = match api_env {
        "xplat" => "api.protect",
        "xplat-reporting" => "api.protect-reporting",
        other => other,
    };

    Ok(format!("https://{}.{}", subdomain, domain_part))
}

pub(crate) fn get_api_version_part(version: u8) -> Result<String, String> {
    if !(1..=2).contains(&version) {
        return Err("Version must be between 1 and 2".to_string());
    }

    Ok(format!("/tx_api/v{}", version))
}

pub(crate) fn get_hyper_client() -> Result<
    Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
    Box<dyn std::error::Error>,
> {
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();

    Ok(Client::builder(TokioExecutor::new()).build(https))
}

fn prepare_payload(
    mut payload: Value,
    token: &Option<&str>,
    allowed_commands: &Option<&[String]>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let p_command = payload
        .get("command")
        .ok_or("'command' key not found")?
        .as_str()
        .ok_or("'command' key value is not a string")?;

    if allowed_commands.is_some()
        && !allowed_commands
            .as_ref()
            .ok_or("could not ref 'allowed_commands'")?
            .contains(&p_command.to_string())
    {
        return Err(format!("Command not found: {}", &p_command).into());
    }
    if token.is_some() {
        payload
            .as_object_mut()
            .ok_or("could not get map out of payload")?
            .insert("token".to_string(), json!(token));
    }

    Ok(payload)
}

async fn get_response_body(
    url: &str,
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
    payload: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let bytes_payload = Bytes::from(serde_json::to_vec(&payload)?);

    let request = Request::builder()
        .uri(url)
        .header(hyper::header::USER_AGENT, get_header())
        .method(Method::POST)
        .body(Full::new(bytes_payload))?;

    let res = client.request(request).await?;
    let body = res.collect().await?.aggregate();
    let parsed_body: Value = serde_json::from_reader(body.reader())?;

    Ok(parsed_body)
}

async fn send_single_request(
    url: &str,
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
    payload: &Value,
) -> Result<Value, RequestError> {
    let marker = payload.get("marker");
    if let Some(marker) = marker
        && !marker.is_string()
        && !marker.is_number()
    {
        return Err(RequestError::ProcessingError(json!(
            "Incorrect marker value provided"
        )));
    }

    let parsed_body = get_response_body(url, client, payload)
        .await
        .map_err(|error| {
            if marker.is_some() {
                return RequestError::ProcessingError(
                    json!({"error": error.to_string(), "marker": marker}),
                );
            }
            RequestError::ProcessingError(json!(error.to_string()))
        })?;

    if let Some(ok) = parsed_body.get("Ok") {
        if marker.is_some() {
            return Ok(json!({"data": ok, "marker": marker}));
        }
        return Ok(ok.clone());
    }
    if let Some(error) = parsed_body.get("Error") {
        if error == "Token Expired. Please re-authenticate." {
            return Err(RequestError::TokenExpired);
        }
        if marker.is_some() {
            return Err(RequestError::ResponseError(
                json!({"error": error, "marker": marker}),
            ));
        }
        return Err(RequestError::ResponseError(error.clone()));
    }
    Err(RequestError::IncorrectState)
}

#[allow(clippy::too_many_arguments)]
async fn process_single_request(
    url: &str,
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
    allowed_commands: &[String],
    payload: Value,
    token: Arc<RwLock<String>>,
    token_refresh_lock: Arc<Mutex<()>>,
    api_env: &str,
    api_key: &str,
) -> Result<Value, String> {
    let current_token = token.read().await.clone();

    let payload = prepare_payload(payload, &Some(&current_token), &Some(allowed_commands))
        .map_err(|e| format!("{:?}", e))?;

    let response = send_single_request(url, client, &payload).await;

    match response {
        Err(RequestError::TokenExpired) => {
            let current_token = {
                let _refresh_guard = token_refresh_lock.lock().await;

                let current = token.read().await.clone();
                if current == current_token {
                    let refreshed = login(api_env, api_key, client)
                        .await
                        .map_err(|e| format!("{:?}", e))?;
                    *token.write().await = refreshed.clone();
                    refreshed
                } else {
                    current
                }
            };

            let payload = prepare_payload(payload, &Some(&current_token), &Some(allowed_commands))
                .map_err(|e| format!("{:?}", e))?;

            send_single_request(url, client, &payload)
                .await
                .map_err(|e| format!("{:?}", e))
        }
        Ok(val) => Ok(val),
        Err(e) => Err(format!("{:?}", e)),
    }
}

pub(crate) async fn process_requests(
    url: &str,
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
    allowed_commands: Vec<String>,
    token: String,
    api_env: &str,
    api_key: &str,
    payloads: Vec<Value>,
) -> Result<Vec<Result<Value, String>>, Box<dyn std::error::Error>> {
    let semaphore = Arc::new(Semaphore::new(70));
    let token = Arc::new(RwLock::new(token));
    let token_refresh_lock = Arc::new(Mutex::new(()));
    let mut task_set = JoinSet::new();

    let url = url.to_string();
    let client = client.clone();
    let api_env = api_env.to_string();
    let api_key = api_key.to_string();
    let allowed_commands = Arc::new(allowed_commands);

    for payload in payloads {
        let semaphore = semaphore.clone();
        let token = Arc::clone(&token);
        let token_refresh_lock = Arc::clone(&token_refresh_lock);
        let url = url.clone();
        let client = client.clone();
        let api_env = api_env.clone();
        let api_key = api_key.clone();
        let allowed_commands = Arc::clone(&allowed_commands);

        task_set.spawn(async move {
            let _semaphore_permit = semaphore.acquire().await.map_err(|e| e.to_string())?;

            process_single_request(
                &url,
                &client,
                &allowed_commands,
                payload,
                token,
                token_refresh_lock,
                &api_env,
                &api_key,
            )
            .await
        });
    }

    Ok(task_set.join_all().await)
}

pub(crate) async fn login(
    api_env: &str,
    api_key: &str,
    client: &Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        Full<Bytes>,
    >,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!(
        "{}{}/login",
        get_api_host_part(api_env)?,
        get_api_version_part(1)?,
    );

    let payload = prepare_payload(
        json!({ "api_token": api_key, "command": "login" }),
        &None,
        &None,
    )?;

    let response = send_single_request(&url, client, &payload).await;

    let token = match response {
        Ok(login_response_value) => login_response_value
            .get("token")
            .ok_or("Failed to get token value")?
            .clone(),
        Err(err) => return Err(format!("Failed to get login response: {:?}", err).into()),
    };

    if token.is_null() {
        return Err("Failed to get token".into());
    }

    Ok(token.as_str().ok_or("token is not a string")?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_header_contains_package_name() {
        assert!(get_header().contains("ThreatX-Rust-API-Client/"))
    }
    #[test]
    fn get_api_host_part_handles_xplat_path() {
        assert_eq!(
            get_api_host_part("xplat"),
            Ok("https://api.protect.threatx.io".into())
        )
    }
    #[test]
    fn get_api_host_part_handles_custom_path() {
        assert_eq!(
            get_api_host_part("pratect.please"),
            Ok("https://pratect.please.threatx.io".into())
        )
    }
    #[test]
    fn get_api_host_part_handles_no_path() {
        assert!(get_api_host_part("").is_err())
    }
    #[test]
    fn prepare_payload_errors_for_incorrect_command() {
        let payload = json!({ "command": "login" });
        let allowed_commands = vec!["limao".to_string(), "something".to_string()];
        assert!(prepare_payload(payload, &Some(""), &Some(&allowed_commands)).is_err())
    }
    #[test]
    fn prepare_payload_result_contains_token() {
        let payload = json!({ "command": "login" });
        let token_value = "1234xyz";
        let allowed_commands = vec!["login".to_string(), "something".to_string()];
        let result =
            prepare_payload(payload, &Some(token_value), &Some(&allowed_commands)).unwrap();
        assert_eq!(result.get("token").unwrap(), token_value);
    }
}
