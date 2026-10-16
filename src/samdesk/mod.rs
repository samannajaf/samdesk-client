// SamDesk: role lock (customer = incoming only, supporter = outgoing only)
// and signed support tickets issued by samdesk-auth. Server address, relay and
// public key are already baked in by the branding in hbb_common::config, so
// this module only adds the role/ticket layer on top of it.
pub mod ticket;

use hbb_common::{
    base64::{engine::general_purpose::STANDARD, Engine as _},
    config::{self, Config},
    log, serde_json,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

const AUTH_URL: &str = "https://samdesk.ir/api/v1";
const OPT_TOKEN: &str = "samdesk-token";
const OPT_CUSTOMER: &str = "samdesk-customer-id";
const OPT_SECRET: &str = "samdesk-secret";
const HEARTBEAT_SECS: u64 = 60;

pub fn is_customer() -> bool {
    cfg!(feature = "samdesk_customer")
}

pub fn is_supporter() -> bool {
    cfg!(feature = "samdesk_support")
}

fn auth_pubkey() -> Vec<u8> {
    STANDARD
        .decode(include_str!("auth-pubkey.txt").trim())
        .unwrap_or_default()
}

pub fn initialize() {
    {
        let mut o = config::OVERWRITE_SETTINGS.write().unwrap();
        if is_customer() {
            o.insert("approve-mode".to_owned(), "click".to_owned());
            // Allow direct LAN connections: a supporter on the same local
            // network can reach the customer by its internal IP without the
            // server/relay. Incoming connections still require a valid signed
            // ticket (verified locally against the built-in key) and the
            // customer's click approval, so this does not weaken access control.
            o.insert("direct-server".to_owned(), "Y".to_owned());
            o.insert("enable-lan-discovery".to_owned(), "Y".to_owned());
            o.insert("allow-remote-config-modification".to_owned(), "N".to_owned());
        } else if is_supporter() {
            // Let a supporter discover and connect to customers on the same LAN.
            o.insert("enable-lan-discovery".to_owned(), "Y".to_owned());
        }
    }
    {
        let mut h = config::HARD_SETTINGS.write().unwrap();
        if is_customer() {
            h.insert("conn-type".to_owned(), "incoming".to_owned());
        } else if is_supporter() {
            h.insert("conn-type".to_owned(), "outgoing".to_owned());
        }
    }
    if is_customer() {
        remember_token();
    }
}

// ---------------- customer side ----------------

#[derive(Default)]
struct State {
    activated: bool,
    revoked: bool,
    revoked_supporters: HashSet<String>,
    used_jti: HashMap<String, i64>,
}

lazy_static::lazy_static! {
    static ref STATE: Mutex<State> = Default::default();
}

pub enum Denied {
    /// No ticket in the request: ask the supporter to paste one into the password box.
    NeedTicket,
    Refused(&'static str),
}

/// Called by the customer's connection handler for every LoginRequest.
pub fn check_login(ticket: &str, peer_id: &str) -> Result<(), Denied> {
    if !is_customer() {
        return Ok(());
    }
    if ticket.is_empty() {
        return Err(Denied::NeedTicket);
    }
    let now = hbb_common::get_time() / 1000;
    let t = match ticket::verify(&auth_pubkey(), ticket, now) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("samdesk: ticket rejected: {:?}", e);
            return Err(Denied::Refused("SamDesk: invalid or expired ticket"));
        }
    };
    if t.rid != Config::get_id() {
        return Err(Denied::Refused("SamDesk: ticket is for another device"));
    }
    let peer = peer_id.split('@').next().unwrap_or_default();
    if !t.peer.is_empty() && t.peer != peer {
        return Err(Denied::Refused("SamDesk: ticket is for another supporter device"));
    }
    let mut st = STATE.lock().unwrap();
    if !st.activated {
        return Err(Denied::Refused("SamDesk: this copy is not activated"));
    }
    if st.revoked {
        return Err(Denied::Refused("SamDesk: this copy has been revoked"));
    }
    if st.revoked_supporters.contains(&t.sup) {
        return Err(Denied::Refused("SamDesk: supporter account is closed"));
    }
    st.used_jti.retain(|_, exp| *exp > now);
    if st.used_jti.insert(t.jti.clone(), t.exp).is_some() {
        return Err(Denied::Refused("SamDesk: ticket already used"));
    }
    log::info!("samdesk: ticket accepted, supporter {} ({})", t.user, t.sup);
    Ok(())
}

fn device_id() -> String {
    crate::get_hwid()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

// The self-extracting package passes its own (downloaded) file name in an env var.
fn token_from_exe() -> Option<String> {
    if let Ok(name) = std::env::var(crate::common::PORTABLE_APPNAME_RUNTIME_ENV_KEY) {
        if let Some(t) = ticket::token_from_file_name(&name) {
            return Some(t);
        }
    }
    let exe = std::env::current_exe().ok()?;
    ticket::token_from_file_name(exe.file_name()?.to_str()?)
}

fn remember_token() {
    if let Some(t) = token_from_exe() {
        if Config::get_option(OPT_TOKEN) != t {
            Config::set_option(OPT_TOKEN.to_owned(), t);
        }
    }
}

async fn post(path: &str, body: serde_json::Value) -> Option<(u16, serde_json::Value)> {
    match crate::post_request_with_status(
        format!("{AUTH_URL}{path}"),
        body.to_string(),
        "Content-Type: application/json",
    )
    .await
    {
        Ok((code, text)) => Some((code, serde_json::from_str(&text).unwrap_or_default())),
        Err(e) => {
            log::warn!("samdesk: {} failed: {}", path, e);
            None
        }
    }
}

fn pubkey_matches(v: &serde_json::Value) -> bool {
    let ok = v["pubkey"].as_str().and_then(|k| STANDARD.decode(k).ok()) == Some(auth_pubkey());
    if !ok {
        log::error!("samdesk: server ticket key does not match the built-in key");
    }
    ok
}

fn apply_status(v: &serde_json::Value) {
    let mut st = STATE.lock().unwrap();
    if let Some(list) = v["revoked_supporters"].as_array() {
        st.revoked_supporters = list
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect();
    }
    st.revoked = v["revoked"].as_bool().unwrap_or(false);
}

async fn activate() -> bool {
    remember_token();
    let token = Config::get_option(OPT_TOKEN);
    if token.is_empty() {
        log::error!("samdesk: no activation token; download the program again with a code");
        return false;
    }
    let body = serde_json::json!({
        "token": token,
        "device": device_id(),
        "rustdesk_id": Config::get_id(),
        "hostname": crate::common::hostname(),
    });
    let Some((code, v)) = post("/customer/activate", body).await else {
        return false;
    };
    if code != 200 || !pubkey_matches(&v) {
        log::error!("samdesk: activation refused ({}): {}", code, v["error"]);
        return false;
    }
    let (Some(id), Some(secret)) = (v["customer_id"].as_str(), v["secret"].as_str()) else {
        return false;
    };
    Config::set_option(OPT_CUSTOMER.to_owned(), id.to_owned());
    Config::set_option(OPT_SECRET.to_owned(), secret.to_owned());
    apply_status(&v);
    STATE.lock().unwrap().activated = true;
    log::info!("samdesk: activated as customer {}", id);
    true
}

/// Returns false when the server says the stored credentials are no longer valid.
async fn heartbeat() -> bool {
    let body = serde_json::json!({
        "customer_id": Config::get_option(OPT_CUSTOMER),
        "secret": Config::get_option(OPT_SECRET),
        "device": device_id(),
        "rustdesk_id": Config::get_id(),
    });
    match post("/customer/heartbeat", body).await {
        Some((200, v)) if pubkey_matches(&v) => {
            apply_status(&v);
            STATE.lock().unwrap().activated = true;
            true
        }
        Some((403, v)) => {
            apply_status(&v);
            if v["revoked"].as_bool() != Some(true) {
                STATE.lock().unwrap().activated = false;
                return false;
            }
            true
        }
        // network problems keep the last known state
        _ => true,
    }
}

/// Started once in the process that accepts connections.
pub fn start_agent() {
    if !is_customer() {
        return;
    }
    // credentials from an earlier run stay valid while samdesk.ir is unreachable
    STATE.lock().unwrap().activated = !Config::get_option(OPT_SECRET).is_empty();
    hbb_common::tokio::spawn(async {
        loop {
            let has_secret = !Config::get_option(OPT_SECRET).is_empty();
            let ok = if has_secret {
                heartbeat().await || activate().await
            } else {
                activate().await
            };
            if !ok && !has_secret {
                STATE.lock().unwrap().activated = false;
            }
            hbb_common::sleep(HEARTBEAT_SECS as f32).await;
        }
    });
}
