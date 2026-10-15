// FvConnect license gate.
//
// Before relaying a connection request (punch hole or relay), hbbs asks the FvConnect portal
// whether the technician's login token may connect. The client already sends its account
// access token in PunchHoleRequest.token / RequestRelay.token.
//
// Environment:
//   FV_ENFORCE=Y      turns the gate on (off by default, so deploying this build changes nothing)
//   FV_PORTAL_URL     e.g. https://portal.example/api/fv/authorize
//   FV_SERVER_KEY     shared secret shown in the portal (Admin > Servidor e licenças)

use hbb_common::log;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

const ALLOW_TTL: Duration = Duration::from_secs(15);
const DENY_TTL: Duration = Duration::from_secs(15);
// If the portal is unreachable, a token that was allowed recently keeps working for a while.
const STALE_ALLOW: Duration = Duration::from_secs(6 * 60 * 60);
const MAX_CACHE: usize = 10_000;

const MSG_NO_LOGIN: &str = "Entre na sua conta FvConnect (botão Conta) para acessar outros computadores.";
const MSG_UNAVAILABLE: &str = "Não foi possível validar a licença FvConnect agora. Tente de novo em instantes.";

struct Decision {
    allow: bool,
    message: String,
    at: Instant,
}

static CACHE: Lazy<Mutex<HashMap<String, Decision>>> = Lazy::new(|| Mutex::new(HashMap::new()));

static CLIENT: Lazy<Option<reqwest::Client>> = Lazy::new(|| {
    match reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(c) => Some(c),
        Err(e) => {
            log::error!("FvConnect: failed to build http client: {}", e);
            None
        }
    }
});

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_owned()
}

pub fn enforced() -> bool {
    matches!(env("FV_ENFORCE").as_str(), "Y" | "y" | "1" | "true")
}

fn cached(token: &str, max_age_allow: Duration) -> Option<Result<(), String>> {
    let cache = CACHE.lock().unwrap();
    let d = cache.get(token)?;
    let age = d.at.elapsed();
    if d.allow && age < max_age_allow {
        Some(Ok(()))
    } else if !d.allow && age < DENY_TTL {
        Some(Err(d.message.clone()))
    } else {
        None
    }
}

fn remember(token: &str, allow: bool, message: String) {
    let mut cache = CACHE.lock().unwrap();
    if cache.len() >= MAX_CACHE {
        cache.retain(|_, d| d.at.elapsed() < STALE_ALLOW);
        if cache.len() >= MAX_CACHE {
            cache.clear();
        }
    }
    cache.insert(
        token.to_owned(),
        Decision {
            allow,
            message,
            at: Instant::now(),
        },
    );
}

async fn ask_portal(token: &str, target: &str) -> Result<(bool, String), String> {
    let url = env("FV_PORTAL_URL");
    let key = env("FV_SERVER_KEY");
    if url.is_empty() || key.is_empty() {
        return Err("FV_PORTAL_URL / FV_SERVER_KEY not set".to_owned());
    }
    let client = CLIENT.as_ref().ok_or("no http client")?;
    let res = client
        .post(&url)
        .header("x-fv-server-key", key)
        .json(&serde_json::json!({ "token": token, "target": target }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("portal answered {}", res.status()));
    }
    let v: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    let allow = v["allow"].as_bool().unwrap_or(false);
    let message = v["message"].as_str().unwrap_or("Acesso não autorizado.").to_owned();
    Ok((allow, message))
}

/// Ok(()) lets the connection through; Err(message) refuses it and the message is shown
/// to the technician.
pub async fn authorize(token: &str, target: &str) -> Result<(), String> {
    if !enforced() {
        return Ok(());
    }
    if token.is_empty() {
        return Err(MSG_NO_LOGIN.to_owned());
    }
    if let Some(r) = cached(token, ALLOW_TTL) {
        return r;
    }
    match ask_portal(token, target).await {
        Ok((allow, message)) => {
            remember(token, allow, message.clone());
            if allow {
                Ok(())
            } else {
                Err(message)
            }
        }
        Err(e) => {
            log::warn!("FvConnect: license check failed for {}: {}", target, e);
            match cached(token, STALE_ALLOW) {
                Some(Ok(())) => Ok(()),
                _ => Err(MSG_UNAVAILABLE.to_owned()),
            }
        }
    }
}
