//! Параметры: outproxy в сети I2P и адрес HTTP-прокси i2pd.

use penguin_core::address::Address;
use penguin_core::endpoint::ServerEndpoint;
use serde::{Deserialize, Serialize};

use crate::error::{I2pError, I2pResult};

/// Outproxy по умолчанию.
pub const DEFAULT_OUTPROXY: &str =
    "http://vdipaav5qboynfekbc6ngovng6svgmo2vux5s5iqyuz3c6zf7paa.b32.i2p";

/// HTTP-прокси i2pd: его порт по умолчанию, его же ставит движок.
pub const DEFAULT_PROXY: &str = "127.0.0.1:4444";

/// Порт outproxy, если не указан: так его зовёт и сам i2pd.
const OUTPROXY_PORT: u16 = 80;

/// Длина имени `.b32.i2p` (SHA-256 в base32); у зашифрованного набора (b33) — от 56.
const B32_LEN: usize = 52;
const B33_MIN_LEN: usize = 56;

/// Настройки выхода через I2P.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct I2pConfig {
    /// Outproxy: `http://<имя>.b32.i2p`, порт можно указать.
    #[serde(default = "default_outproxy")]
    pub outproxy: String,

    /// HTTP-прокси i2pd.
    #[serde(default = "default_proxy")]
    pub proxy: String,
}

fn default_outproxy() -> String {
    DEFAULT_OUTPROXY.to_owned()
}

fn default_proxy() -> String {
    DEFAULT_PROXY.to_owned()
}

impl I2pConfig {
    /// Адрес HTTP-прокси i2pd.
    pub fn proxy_endpoint(&self) -> I2pResult<(Address, u16)> {
        let raw = self.proxy.trim();
        let endpoint: ServerEndpoint = raw
            .parse()
            .map_err(|e| I2pError::config(format!("адрес прокси i2pd `{raw}`: {e}")))?;
        if endpoint.ports.is_hopping() {
            return Err(I2pError::config("у прокси i2pd один порт"));
        }
        Ok((endpoint.host, endpoint.ports.first()))
    }

    /// Outproxy как `имя.b32.i2p:порт` — так его называет первый `CONNECT`.
    pub fn outproxy_authority(&self) -> I2pResult<String> {
        parse_outproxy(&self.outproxy)
    }

    /// Проверяет настройки без сети.
    pub fn validate(&self) -> I2pResult<()> {
        self.proxy_endpoint()?;
        self.outproxy_authority()?;
        Ok(())
    }
}

/// `http://Имя.b32.i2p/` → `имя.b32.i2p:80`; другие схемы и имена из адресной книги — отказ.
fn parse_outproxy(raw: &str) -> I2pResult<String> {
    let bad = |why: &str| I2pError::config(format!("outproxy `{raw}`: {why}"));
    let trimmed = raw.trim();
    let rest = match trimmed.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
        Some(_) => return Err(bad("outproxy в I2P — HTTP-прокси, схема только `http://`")),
        None => trimmed,
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| bad("порт не число от 1 до 65535"))?,
        ),
        None => (rest, OUTPROXY_PORT),
    };

    let host = host.to_ascii_lowercase();
    let label = host
        .strip_suffix(".b32.i2p")
        .ok_or_else(|| bad("нужен адрес `.b32.i2p`: адресной книги у i2pd движка нет"))?;
    let base32 = label
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'));
    if !base32 || !(label.len() == B32_LEN || label.len() >= B33_MIN_LEN) {
        return Err(bad("имя `.b32.i2p` — 52 знака base32 (a–z, 2–7)"));
    }
    Ok(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NAME: &str = "vdipaav5qboynfekbc6ngovng6svgmo2vux5s5iqyuz3c6zf7paa.b32.i2p";

    fn outproxy(raw: &str) -> I2pResult<String> {
        parse_outproxy(raw)
    }

    #[test]
    fn every_spelling_of_the_outproxy_names_one_destination() {
        let expected = format!("{NAME}:80");
        for raw in [
            format!("http://{NAME}"),
            format!("http://{NAME}/"),
            format!("HTTP://{}", NAME.to_ascii_uppercase()),
            NAME.to_owned(),
            format!("{NAME}:80"),
        ] {
            assert_eq!(outproxy(&raw).expect(&raw), expected);
        }
        assert_eq!(
            outproxy(&format!("http://{NAME}:4444")).expect("порт"),
            format!("{NAME}:4444")
        );
    }

    #[test]
    fn names_outside_b32_are_refused() {
        for raw in [
            "http://exit.stormycloud.i2p",
            "https://vdipaav5qboynfekbc6ngovng6svgmo2vux5s5iqyuz3c6zf7paa.b32.i2p",
            "http://short.b32.i2p",
            "http://vdipaav5qboynfekbc6ngovng6svgmo2vux5s5iqyuz3c6zf7pa1.b32.i2p",
            "http://vdipaav5qboynfekbc6ngovng6svgmo2vux5s5iqyuz3c6zf7paa.b32.i2p:0",
            "example.com:3128",
            "",
        ] {
            assert!(outproxy(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn an_empty_profile_takes_the_defaults() {
        let config: I2pConfig = serde_json::from_value(json!({})).expect("разбирается");
        config.validate().expect("умолчания верны");
        assert_eq!(config.proxy, DEFAULT_PROXY);
        assert_eq!(
            config.outproxy_authority().expect("адрес"),
            format!("{NAME}:80")
        );
    }

    #[test]
    fn rejects_an_unknown_field() {
        assert!(serde_json::from_value::<I2pConfig>(json!({ "outproxi": NAME })).is_err());
    }

    #[test]
    fn the_proxy_needs_one_port() {
        let config = I2pConfig {
            outproxy: NAME.to_owned(),
            proxy: "127.0.0.1:4444-4445".to_owned(),
        };
        assert!(config.validate().is_err());
    }
}
