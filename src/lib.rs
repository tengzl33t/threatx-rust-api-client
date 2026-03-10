use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use hyper;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Buf, Request};
use serde::Deserialize;

use std::collections::HashMap;
use std::fmt::format;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

fn get_header() -> String {
    format!("ThreatX-Rust-API-Client/{}", env!("CARGO_PKG_VERSION"))
}

fn get_api_host_part(api_env: &str) -> String {
    let predefined_envs: HashMap<&str, &str>  = HashMap::from_iter(
        [
            ("xplat", "protect"),
            ("xplat-reporting", "protect-reporting")
        ]
    );
    let domain_part = "threatx.io".to_string();

    if predefined_envs.contains_key(api_env) {
        return format!("https://api.{}.{}", predefined_envs[api_env], domain_part);
    }

    format!("https://{}.{}", api_env, domain_part)
}

fn get_api_version_part(version: u8) -> Result<String, String> {
    if version < 1 || version > 2 {
        return Err("Version must be between 1 and 2".to_string());
    }

    Ok(format!("/tx_api/v{}", version))
}
#[tokio::main]
async fn process_requests() -> Result<Vec<String>, hyper::Error> {
    let url = "https://jsonplaceholder.typicode.com/todos/1".parse::<hyper::Uri>()?;
    let host = url.host().expect("uri has no host");
    let port = url.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);
    println!("addr: {}", addr);
    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    let authority = url.authority().unwrap().clone();

    // Fetch the url...
    let req = Request::builder()
        .uri(url)
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())?;

    let res = sender.send_request(req).await?;

    // asynchronously aggregate the chunks of the body
    let body = res.collect().await?.aggregate();
    // try to parse as json with serde_json
    let parsed_body = serde_json::from_reader(body.reader())?;

    println!("{}", parsed_body);
    Ok("".to_string())
}

fn login(api_env: &str, api_key: &str) -> String {
    let url = format!(
        "{}{}/login",
        get_api_host_part(api_env),
        get_api_version_part(1).unwrap(),
    );
    url
}

#[tokio::main]
async fn main() -> Result<String, String> {
    process_requests()
}


// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn it_works() {
//         // get_api_host("api");
//         println!("{}", get_api_version_part(1).unwrap());
//         println!("{}", get_header());
//         println!("{}", process_requests());
//     }
// }
