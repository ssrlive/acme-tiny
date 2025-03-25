use base64::{Engine as _, engine::general_purpose};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::Write,
    time::{Duration, Instant},
};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    dotenvy::dotenv().ok();
    let args = <CommandLineArgs as ::clap::Parser>::parse();

    use log::LevelFilter::{Error, Trace};
    let v = if args.quiet { Error } else { Trace };
    let default = format!("{}={:?}", module_path!(), v);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let signed_crt = get_crt(&args).await?;
    if let Some(output) = args.output {
        std::fs::write(output, signed_crt)?;
    } else {
        print!("{}", signed_crt);
    }
    Ok(())
}

const DEFAULT_DIRECTORY_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct Jwk {
    e: String,
    kty: String,
    n: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct Protected {
    url: String,
    alg: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct AcmeRequest {
    protected: String,
    payload: String,
    signature: String,
}

fn b64(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn cmd(command: &str, args: &[&str], input: Option<&[u8]>) -> std::io::Result<Vec<u8>> {
    let full_cmd = format!("{} {}", command, args.join(" "));
    log::debug!("Running command: \"{full_cmd}\"...");
    use std::process::{Command, Stdio};
    let mut cmd = Command::new(command);
    cmd.args(args);
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }

    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;

    if let Some(input_data) = input {
        use std::io::{Error, ErrorKind::Other};
        let err = Error::new(Other, format!("Failed to open stdin for command: \"{full_cmd}\""));
        child.stdin.as_mut().ok_or(err)?.write_all(input_data)?;
    }

    let out = match child.wait_with_output() {
        Ok(out) => out,
        Err(e) => {
            let e2 = e.to_string().trim().to_string();
            log::error!("Run command: \"{full_cmd}\" failed with: \"{e2}\"");
            return Err(e);
        }
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        let info = format!("Run command: \"{full_cmd}\" not success with \"{}\"", err.trim());
        log::error!("{}", info);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

// make request and automatically parse json response
async fn do_request(url: &str, data: Option<&[u8]>) -> Result<(serde_json::Value, u16, reqwest::header::HeaderMap), BoxError> {
    let client = reqwest::Client::new();
    let request = if let Some(data) = data {
        client.post(url).header("Content-Type", "application/jose+json").body(data.to_vec())
    } else {
        client.get(url)
    };
    let response = request.header("User-Agent", env!("CARGO_PKG_NAME")).send().await?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = response.text().await?;
    let json: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::String(text));

    Ok((json, status, headers))
}

#[allow(clippy::too_many_arguments)]
async fn send_signed_request(
    url: &str,
    payload: Option<&serde_json::Value>,
    account_key: &str,
    directory: &serde_json::Value,
    acct_headers: Option<&reqwest::header::HeaderMap>,
    jwk: &Jwk,
    alg: &str,
    depth: u32,
) -> Result<(serde_json::Value, u16, reqwest::header::HeaderMap), BoxError> {
    let payload64 = match payload {
        Some(p) => b64(serde_json::to_string(p)?.as_bytes()),
        None => String::new(),
    };

    let nonce = directory["newNonce"].as_str().ok_or("No newNonce URL")?;
    let e = "No Replay-Nonce header";
    let new_nonce = do_request(nonce, None).await?.2.get("Replay-Nonce").ok_or(e)?.to_str()?.to_string();

    let mut protected = Protected {
        url: url.to_string(),
        alg: alg.to_string(),
        nonce: new_nonce,
        ..Protected::default()
    };

    match acct_headers {
        None => protected.jwk = Some(jwk.clone()),
        Some(hdr) => protected.kid = hdr.get("Location").and_then(|loc| loc.to_str().ok()).map(|loc| loc.to_string()),
    }

    let protected64 = b64(serde_json::to_string(&protected)?.as_bytes());
    let protected_input = format!("{}.{}", protected64, payload64).into_bytes();

    let signature = b64(&cmd("openssl", &["dgst", "-sha256", "-sign", account_key], Some(&protected_input))?);
    let request = AcmeRequest {
        protected: protected64,
        payload: payload64,
        signature,
    };

    let data = serde_json::to_string(&request)?;
    let (resp_data, code, headers) = do_request(url, Some(data.as_bytes())).await?;

    if depth < 100 && code == 400 && resp_data["type"] == "urn:ietf:params:acme:error:badNonce" {
        let d = depth + 1;
        log::debug!("Retrying request due to bad nonce, attempt {}", d);
        return Box::pin(send_signed_request(url, payload, account_key, directory, acct_headers, jwk, alg, d)).await;
    }

    if ![200, 201, 204].contains(&code) {
        return Err(format!("Error: \nUrl: {url}\nData: {data}\nResponse Code: {code}\nResponse: {resp_data}").into());
    }

    Ok((resp_data, code, headers))
}

async fn poll_until_not(
    url: &str,
    pending_statuses: &[&str],
    account_key: &str,
    directory: &serde_json::Value,
    acct_headers: Option<&reqwest::header::HeaderMap>,
    jwk: &Jwk,
    alg: &str,
) -> Result<serde_json::Value, BoxError> {
    let start = Instant::now();
    let mut result: Option<serde_json::Value> = None;

    while result.is_none() || pending_statuses.contains(&result.as_ref().ok_or("No result")?["status"].as_str().ok_or("No status")?) {
        // 1 hour timeout
        if start.elapsed() >= Duration::from_secs(3600) {
            return Err("Polling timeout".into());
        }

        if result.is_some() {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        let (resp_data, _, _) = send_signed_request(url, None, account_key, directory, acct_headers, jwk, alg, 0).await?;
        result = Some(resp_data);
    }

    Ok(result.ok_or("No result")?)
}

async fn get_crt(args: &CommandLineArgs) -> Result<String, BoxError> {
    let CommandLineArgs {
        account_key,
        csr,
        acme_dir,
        disable_check,
        directory_url,
        contact,
        check_port,
        ..
    } = args;
    let account_key = account_key.to_str().ok_or("No account key path")?;
    let csr = csr.to_str().ok_or("No CSR path")?;

    log::info!("Parsing account key...");
    let out = cmd("openssl", &["rsa", "-in", account_key, "-noout", "-text"], None)?;
    let out_str = String::from_utf8(out)?;
    let pub_pattern = Regex::new(r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)")?;
    let captures = pub_pattern.captures(&out_str).ok_or("No public key")?;
    let pub_hex = captures.get(1).ok_or("No public key hex")?.as_str();
    let mut pub_exp = format!("{:x}", captures[2].parse::<i64>()?);
    if pub_exp.len() % 2 != 0 {
        pub_exp = format!("0{}", pub_exp);
    }

    let alg = "RS256";
    let jwk = Jwk {
        e: b64(&hex::decode(&pub_exp)?),
        kty: "RSA".to_string(),
        n: b64(&hex::decode(pub_hex.replace(&[':', ' ', '\n'][..], ""))?),
    };

    let accountkey_json = serde_json::to_string(&jwk)?;

    let thumbprint = {
        let mut hasher = <::sha2::Sha256 as ::sha2::Digest>::new();
        ::sha2::Digest::update(&mut hasher, accountkey_json.as_bytes());
        let hash_result = ::sha2::Digest::finalize(hasher);
        b64(&hash_result)
    };

    log::info!("Parsing CSR...");
    let out = cmd("openssl", &["req", "-in", csr, "-noout", "-text"], None)?;
    let out_str = String::from_utf8(out)?;
    let mut domains = HashSet::new();

    if let Some(cn) = Regex::new(r"Subject:.*? CN\s?=\s?([^\s,;/]+)")?.captures(&out_str) {
        domains.insert(cn[1].to_string());
    }

    if let Some(subject_alt_names) = Regex::new(r"X509v3 Subject Alternative Name: (?:critical)?\n +([^\n]+)\n")?.captures(&out_str) {
        for san in subject_alt_names[1].split(", ") {
            if let Some(stripped) = san.strip_prefix("DNS:") {
                domains.insert(stripped.to_string());
            }
        }
    }
    log::info!(
        "Found domains: {}",
        domains.iter().map(|d| d.to_owned()).collect::<Vec<_>>().join(", ")
    );

    log::info!("Getting directory...");
    let (directory, _, _) = do_request(&directory_url, None).await?;
    log::info!("Directory found!");

    // create account, update contact details (if any), and set the global key identifier
    log::info!("Registering account...");
    let reg_payload = if let Some(contact) = contact {
        serde_json::json!({"termsOfServiceAgreed": true, "contact": contact})
    } else {
        serde_json::json!({"termsOfServiceAgreed": true})
    };

    let url = directory["newAccount"].as_str().ok_or("No newAccount URL")?;
    let (_account, code, acct_headers) = send_signed_request(url, Some(&reg_payload), account_key, &directory, None, &jwk, alg, 0).await?;
    log::info!(
        "{} Account ID: {}",
        if code == 201 { "Registered!" } else { "Already registered!" },
        acct_headers.get("Location").ok_or("No location header")?.to_str()?
    );

    if let Some(contact) = &contact {
        let url = acct_headers.get("Location").ok_or("No location header")?.to_str()?.to_owned();
        let payload = serde_json::json!({"contact": contact});
        let (account, _, _) = send_signed_request(&url, Some(&payload), account_key, &directory, Some(&acct_headers), &jwk, alg, 0).await?;
        log::info!(
            "Updated contact details:\n{}",
            account["contact"]
                .as_array()
                .ok_or("No contact array")?
                .iter()
                .map(|c| c.as_str().unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    log::info!("Creating new order...");
    let url = directory["newOrder"].as_str().ok_or("No newOrder URL")?;
    let payload =
        serde_json::json!({"identifiers": domains.iter().map(|d| serde_json::json!({"type": "dns", "value": d})).collect::<Vec<_>>()});
    let (order, _, order_headers) =
        send_signed_request(url, Some(&payload), account_key, &directory, Some(&acct_headers), &jwk, alg, 0).await?;
    log::info!("Order created!");

    // get the authorizations that need to be completed
    let re_token = Regex::new(r"[^A-Za-z0-9_\-]")?;
    for auth_url in order["authorizations"].as_array().ok_or("No authorizations array")? {
        let url = auth_url.as_str().ok_or("No authorization URL")?;
        let (authorization, _, _) = send_signed_request(url, None, account_key, &directory, Some(&acct_headers), &jwk, alg, 0).await?;
        let domain = authorization["identifier"]["value"].as_str().ok_or("No domain")?.to_string();

        // skip if already valid
        if authorization["status"] == "valid" {
            log::info!("Already verified: {}, skipping...", domain);
            continue;
        }
        log::info!("Verifying {}...", domain);

        // find the http-01 challenge and write the challenge file
        let challenge = authorization["challenges"]
            .as_array()
            .ok_or("No challenges array")?
            .iter()
            .find(|c| c["type"] == "http-01")
            .ok_or("No http-01 challenge")?;

        let token = re_token.replace_all(challenge["token"].as_str().ok_or("No token")?, "_");
        let keyauthorization = format!("{}.{}", token, thumbprint);
        let wellknown_path = acme_dir.join(&*token);

        std::fs::File::create(&wellknown_path)?.write_all(keyauthorization.as_bytes())?;

        // check that the file is in place
        if !disable_check {
            let port = if let Some(port) = check_port {
                format!(":{}", port)
            } else {
                String::new()
            };
            let wellknown_url = format!("http://{}{}/.well-known/acme-challenge/{}", domain, port, token);
            let (resp_data, _, _) = do_request(&wellknown_url, None).await?;
            if resp_data.as_str().ok_or("No response data")? != keyauthorization {
                let w = wellknown_path.display();
                return Err(format!("Wrote file to {w}, but couldn't download {}: mismatch", wellknown_url).into());
            }
        }

        // say the challenge is done
        let url = challenge["url"].as_str().ok_or("No challenge URL")?;
        let payload = serde_json::json!({});
        send_signed_request(url, Some(&payload), account_key, &directory, Some(&acct_headers), &jwk, alg, 0).await?;

        let url = auth_url.as_str().ok_or("No authorization URL")?;
        let authorization = poll_until_not(url, &["pending"], account_key, &directory, Some(&acct_headers), &jwk, alg).await?;

        if authorization["status"] != "valid" {
            return Err(format!("Challenge did not pass for {}: {}", domain, authorization).into());
        }

        std::fs::remove_file(wellknown_path)?;
        log::info!("{} verified!", domain);
    }

    // finalize the order with the csr
    log::info!("Signing certificate...");
    let url = order["finalize"].as_str().ok_or("No finalize URL")?;
    let csr_der = cmd("openssl", &["req", "-in", csr, "-outform", "DER"], None)?;
    let payload = serde_json::json!({"csr": b64(&csr_der)});
    send_signed_request(url, Some(&payload), account_key, &directory, Some(&acct_headers), &jwk, alg, 0).await?;

    // poll the order to monitor when it's done
    let url = order_headers.get("Location").ok_or("No location header")?.to_str()?;
    let statuses = &["pending", "processing"];
    let order = poll_until_not(url, statuses, account_key, &directory, Some(&acct_headers), &jwk, alg).await?;

    if order["status"] != "valid" {
        return Err(format!("Order failed: {}", order).into());
    }

    // download the certificate
    let url = order["certificate"].as_str().ok_or("No certificate URL")?;
    let (certificate_pem, _, _) = send_signed_request(url, None, account_key, &directory, Some(&acct_headers), &jwk, alg, 0).await?;

    log::info!("Certificate signed!");
    Ok(certificate_pem.as_str().ok_or("No certificate PEM")?.to_string())
}

#[derive(Debug, Clone, clap::Parser)]
#[command(author, version = version_info(), long_about = None, about = about_info())]
struct CommandLineArgs {
    /// path to your Let's Encrypt account private key
    #[arg(short, long, value_name = "FILE", required = true)]
    account_key: std::path::PathBuf,

    /// path to your certificate signing request
    #[arg(short, long, value_name = "FILE", required = true)]
    csr: std::path::PathBuf,

    /// path to the .well-known/acme-challenge/ directory
    #[arg(short = 'd', long, value_name = "DIR", required = true)]
    acme_dir: std::path::PathBuf,

    /// suppress output except for errors
    #[arg(long)]
    quiet: bool,

    /// disable checking if the challenge file is hosted correctly
    #[arg(long)]
    disable_check: bool,

    /// certificate authority directory url
    #[arg(long, default_value = DEFAULT_DIRECTORY_URL, value_name = "URL")]
    directory_url: String,

    /// Contact details (e.g. mailto:aaa@bbb.com) for your account-key
    #[arg(long, value_name = "CONTACT", num_args = 0..)]
    contact: Option<Vec<String>>,

    /// what port to use when self-checking the challenge file, default is 80
    #[arg(long, value_name = "PORT")]
    check_port: Option<u16>,

    /// Output the result to a file
    #[arg(short, long, value_name = "FILE")]
    output: Option<std::path::PathBuf>,
}

macro_rules! version_info_macro {
    () => {
        concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), " ", env!("BUILD_TIME"), ")")
    };
}

const fn version_info() -> &'static str {
    version_info_macro!()
}

const fn about_info() -> &'static str {
    concat!(
        "Automates getting a signed TLS certificate from Let's Encrypt using the ACME protocol.\n",
        "It will need to be run on your server and have access to your private account key.\n",
        "Version: ",
        version_info_macro!()
    )
}
