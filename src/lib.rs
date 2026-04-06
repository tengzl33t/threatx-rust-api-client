/*
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.

SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright tengzl33t

Author: tengzl33t
*/
use serde_json::Value;
mod internal;
use crate::internal::{
    ENDPOINT_MAP, get_api_host_part, get_api_version_part, get_hyper_client, login,
    process_requests,
};

pub async fn send_requests(
    api_env: &str,
    api_key: &str,
    endpoint: &str,
    payloads: Vec<Value>,
) -> Result<Vec<Result<Value, String>>, Box<dyn std::error::Error>> {
    let endpoint_config = &ENDPOINT_MAP[endpoint];

    let client = get_hyper_client();
    let token = login(api_env, api_key, &client).await?;

    let url = format!(
        "{}{}/{}",
        get_api_host_part(api_env)?,
        get_api_version_part(endpoint_config.0)?,
        endpoint
    );

    let allowed_commands = endpoint_config.1.iter().map(|s| s.to_string()).collect();

    process_requests(
        &url,
        &client,
        allowed_commands,
        token,
        api_env,
        api_key,
        payloads,
    )
    .await
}

