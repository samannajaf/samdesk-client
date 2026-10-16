// Verification of SamDesk support tickets issued by samdesk-auth.
// Format: SD1.<base64url(payload json)>.<base64url(ed25519 signature over "SD1.<payload>")>
use hbb_common::{
    base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _},
    serde_json,
    sodiumoxide::crypto::sign,
};

pub const PREFIX: &str = "SD1.";

#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    pub jti: String,
    pub sup: String,
    pub user: String,
    pub rid: String,
    pub peer: String,
    pub exp: i64,
}

#[derive(Debug, PartialEq)]
pub enum TicketError {
    Malformed,
    BadSignature,
    Expired,
}

pub fn looks_like_ticket(s: &str) -> bool {
    s.trim().starts_with(PREFIX)
}

pub fn verify(pubkey: &[u8], ticket: &str, now: i64) -> Result<Ticket, TicketError> {
    let ticket = ticket.trim();
    let mut parts = ticket.split('.');
    let (Some("SD1"), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TicketError::Malformed);
    };
    let pk = sign::PublicKey::from_slice(pubkey).ok_or(TicketError::Malformed)?;
    let sig = URL_SAFE_NO_PAD
        .decode(sig)
        .ok()
        .and_then(|s| sign::Signature::from_bytes(&s).ok())
        .ok_or(TicketError::Malformed)?;
    let signed = &ticket[..PREFIX.len() + payload.len()];
    if !sign::verify_detached(&sig, signed.as_bytes(), &pk) {
        return Err(TicketError::BadSignature);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TicketError::Malformed)?;
    let v: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| TicketError::Malformed)?;
    if v["v"].as_i64() != Some(1) {
        return Err(TicketError::Malformed);
    }
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_owned();
    let (iat, exp) = (
        v["iat"].as_i64().ok_or(TicketError::Malformed)?,
        v["exp"].as_i64().ok_or(TicketError::Malformed)?,
    );
    if now >= exp || now + 60 < iat {
        return Err(TicketError::Expired);
    }
    let t = Ticket {
        jti: s("jti"),
        sup: s("sup"),
        user: s("user"),
        rid: s("rid"),
        peer: s("peer"),
        exp,
    };
    if t.jti.is_empty() || t.sup.is_empty() || t.rid.is_empty() {
        return Err(TicketError::Malformed);
    }
    Ok(t)
}

/// Extracts the one-time activation token from a downloaded file name such as
/// `SamDesk-<48 hex>.exe` or `SamDesk-<48 hex> (1).exe`.
pub fn token_from_file_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let start = lower.find("samdesk-")? + "samdesk-".len();
    let hex: String = lower[start..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    (hex.len() == 48).then_some(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(sk: &sign::SecretKey, payload: &str) -> String {
        let head = format!("{}{}", PREFIX, URL_SAFE_NO_PAD.encode(payload));
        let sig = sign::sign_detached(head.as_bytes(), sk);
        format!("{}.{}", head, URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    #[test]
    fn ticket_roundtrip_and_rejections() {
        let (pk, sk) = sign::gen_keypair();
        let p = r#"{"v":1,"jti":"j1","sup":"s1","user":"ali","cust":"c","rid":"123","peer":"","iat":1000,"exp":1600}"#;
        let t = make(&sk, p);
        let ok = verify(pk.as_ref(), &t, 1100).unwrap();
        assert_eq!((ok.rid.as_str(), ok.sup.as_str()), ("123", "s1"));
        assert_eq!(verify(pk.as_ref(), &t, 1600), Err(TicketError::Expired));
        let (pk2, _) = sign::gen_keypair();
        assert_eq!(verify(pk2.as_ref(), &t, 1100), Err(TicketError::BadSignature));
        let forged = t.replacen(
            &URL_SAFE_NO_PAD.encode(p),
            &URL_SAFE_NO_PAD.encode(p.replace("123", "999")),
            1,
        );
        assert_eq!(verify(pk.as_ref(), &forged, 1100), Err(TicketError::BadSignature));
        assert_eq!(verify(pk.as_ref(), "SD1.x", 1100), Err(TicketError::Malformed));
    }

    #[test]
    fn token_from_names() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(token_from_file_name(&format!("SamDesk-{hex}.exe")).as_deref(), Some(hex));
        assert_eq!(token_from_file_name(&format!("SamDesk-{hex} (1).exe")).as_deref(), Some(hex));
        assert_eq!(token_from_file_name("SamDesk.exe"), None);
        assert_eq!(token_from_file_name("SamDesk-1234.exe"), None);
    }
}
