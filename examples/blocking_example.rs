/*
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.

SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright tengzl33t

Author: tengzl33t
*/
use serde_json::json;
use threatx_rust_api_client::send_requests;

fn main() {
    let payloads = vec![
        json!({ "command": "list_blacklist", "customer_name": "tenant1" }),
        json!({ "command": "list_blacklist", "customer_name": "tenant2", "marker": "marker1234" }),
        json!({ "command": "list_blacklist", "customer_name": "tenant3", "marker": "marker9876" }),
        json!({ "command": "list_blacklist", "customer_name": "tenant4" }),
    ];

    let runtime = tokio::runtime::Runtime::new().unwrap();

    let responses = runtime.block_on(send_requests(
        "xplat",
        "YOUR_API_KEY",
        "lists",
        payloads,
    ));
    println!("{:#?}", responses.unwrap());
}
