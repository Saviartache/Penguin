//! Параметры AmneziaWG из конфигурации: junk (`Jc`/`Jmin`/`Jmax`), padding
//! (`S1`–`S4`), магические заголовки (`H1`–`H4`) и поля 1.5/3 (`I1`–`I5`,
//! `header_protection_key`, `content_padding_addition`, `random_trailers`).
//! Разбор и проверка; сам провод — в [`Obfuscation`](super::Obfuscation).

use penguin_core::base64;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{WireguardError, WireguardResult};
use crate::obfs::chain::Chain;
use crate::obfs::engine::{Awg3, Obfuscation, UintRange};
use crate::obfs::protect::{self, HeaderKey};

impl<'de> Deserialize<'de> for UintRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Число - одно значение; строка `lo-hi` - диапазон (как `UintRange` эталона).
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Written {
            Number(u32),
            Text(String),
        }
        match Written::deserialize(deserializer)? {
            Written::Number(value) => Ok(UintRange::single(value)),
            Written::Text(text) => parse_range(&text).map_err(D::Error::custom),
        }
    }
}

impl Serialize for UintRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (lo, hi) = self.bounds();
        if lo == hi {
            serializer.serialize_u32(lo)
        } else {
            serializer.serialize_str(&format!("{lo}-{hi}"))
        }
    }
}

/// Разбирает `lo-hi` или одиночное `n`; `hi < lo` — ошибка (как `FromString` эталона).
fn parse_range(text: &str) -> Result<UintRange, String> {
    let mut parts = text.split('-');
    let lo = parts
        .next()
        .ok_or("пустой диапазон")?
        .trim()
        .parse::<u32>()
        .map_err(|e| format!("нижняя граница диапазона `{text}`: {e}"))?;
    let hi = match parts.next() {
        Some(part) => part
            .trim()
            .parse::<u32>()
            .map_err(|e| format!("верхняя граница диапазона `{text}`: {e}"))?,
        None => lo,
    };
    if parts.next().is_some() {
        return Err(format!("лишняя часть в диапазоне `{text}`"));
    }
    if hi < lo {
        return Err(format!("верх {hi} меньше низа {lo} в диапазоне `{text}`"));
    }
    Ok(UintRange::new(lo, hi))
}

const fn h_init_default() -> UintRange {
    UintRange::single(1)
}
const fn h_response_default() -> UintRange {
    UintRange::single(2)
}
const fn h_cookie_default() -> UintRange {
    UintRange::single(3)
}
const fn h_transport_default() -> UintRange {
    UintRange::single(4)
}

/// Параметры обфускации AmneziaWG. Пустые значения и заголовки 1–4 сводят
/// протокол к обычному WireGuard.
#[derive(Clone, Serialize, Deserialize)]
pub struct AmneziaParams {
    /// Сколько junk-пакетов слать перед рукопожатием (`Jc`).
    #[serde(default)]
    jc: u32,
    /// Наименьшая длина junk-пакета (`Jmin`).
    #[serde(default)]
    jmin: u32,
    /// Наибольшая длина junk-пакета (`Jmax`).
    #[serde(default)]
    jmax: u32,
    /// Случайный padding перед инициацией (`S1`), байт.
    #[serde(default)]
    s1: u16,
    /// Случайный padding перед ответом (`S2`), байт.
    #[serde(default)]
    s2: u16,
    /// Случайный padding перед cookie-ответом (`S3`), байт.
    #[serde(default)]
    s3: u16,
    /// Случайный padding перед пакетом данных (`S4`), байт.
    #[serde(default)]
    s4: u16,
    /// Магический заголовок инициации (`H1`).
    #[serde(default = "h_init_default")]
    h1: UintRange,
    /// Магический заголовок ответа (`H2`).
    #[serde(default = "h_response_default")]
    h2: UintRange,
    /// Магический заголовок cookie-ответа (`H3`).
    #[serde(default = "h_cookie_default")]
    h3: UintRange,
    /// Магический заголовок пакета данных (`H4`).
    #[serde(default = "h_transport_default")]
    h4: UintRange,
    /// Сигнатура перед рукопожатием (`I1`): цепочка тегов `<b 0x…><r 16>…`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i1: Option<String>,
    /// Сигнатура `I2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i2: Option<String>,
    /// Сигнатура `I3`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i3: Option<String>,
    /// Сигнатура `I4`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i4: Option<String>,
    /// Сигнатура `I5`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i5: Option<String>,
    /// Ключ защиты заголовков, base64, 32 байта (`awg genkey`); требует `S1`–`S4` от 12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    header_protection_key: Option<String>,
    /// Добавка к содержимому пакета данных, байт: число или `lo-hi`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_padding_addition: Option<UintRange>,
    /// Случайный хвост после рукопожатия и пакетов данных.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    random_trailers: bool,
    /// Прочее (таймеры AWG 3 и опечатки): не поддержано, ловится в
    /// [`Self::validate`]. Собрано сюда, чтобы отказ был внятным, а не «лишнее поле».
    #[serde(flatten)]
    unsupported: serde_json::Map<String, serde_json::Value>,
}

impl AmneziaParams {
    /// Проверяет параметры, не выходя в сеть (`AGENTS.md` §8).
    pub fn validate(&self) -> WireguardResult<()> {
        self.resolve().map(drop)
    }

    /// Разбирает в готовую к работе обфускацию.
    pub(crate) fn resolve(&self) -> WireguardResult<Obfuscation> {
        if !self.unsupported.is_empty() {
            let mut keys: Vec<&str> = self.unsupported.keys().map(String::as_str).collect();
            keys.sort_unstable();
            return Err(WireguardError::config(format!(
                "поля AmneziaWG не поддержаны (таймеры AWG 3 — местная политика клиента): {}",
                keys.join(", ")
            )));
        }
        if self.jc > 0 && self.jmax < self.jmin {
            return Err(WireguardError::config(format!(
                "jmax ({}) меньше jmin ({})",
                self.jmax, self.jmin
            )));
        }
        let paddings = [self.s1, self.s2, self.s3, self.s4];
        let v3 = Awg3 {
            protection: self.header_key(paddings)?,
            signatures: self.signatures()?,
            // Ноль — добавки нет (`IsZero` эталона).
            content_padding: self
                .content_padding_addition
                .filter(|range| range.bounds() != (0, 0)),
            random_trailers: self.random_trailers,
        };
        Ok(Obfuscation::new(
            self.jc,
            self.jmin,
            self.jmax,
            paddings,
            [self.h1, self.h2, self.h3, self.h4],
        )
        .with_v3(v3))
    }

    /// Ключ защиты; его nonce берётся из `Sx`, поэтому каждый не короче 12.
    fn header_key(&self, paddings: [u16; 4]) -> WireguardResult<Option<HeaderKey>> {
        let Some(text) = &self.header_protection_key else {
            return Ok(None);
        };
        let bytes = base64::decode_exact(text, protect::KEY_LEN, "header_protection_key")
            .map_err(|e| WireguardError::config(e.to_string()))?;
        let mut key = [0u8; protect::KEY_LEN];
        key.copy_from_slice(&bytes);
        if key == [0u8; protect::KEY_LEN] {
            // Нулевой ключ эталон считает отсутствующим.
            return Ok(None);
        }
        for (i, padding) in paddings.iter().enumerate() {
            if usize::from(*padding) < protect::NONCE_LEN {
                return Err(WireguardError::config(format!(
                    "защите заголовков нужен S{} не меньше {}, а он {padding}",
                    i + 1,
                    protect::NONCE_LEN
                )));
            }
        }
        Ok(Some(HeaderKey::new(key)))
    }

    /// Сигнатуры `I1`–`I5` по порядку; записи без тегов пропускаются.
    fn signatures(&self) -> WireguardResult<Vec<Chain>> {
        let specs = [&self.i1, &self.i2, &self.i3, &self.i4, &self.i5];
        let mut chains = Vec::new();
        for (i, spec) in specs.into_iter().enumerate() {
            let Some(spec) = spec else { continue };
            let chain = Chain::parse(spec)
                .map_err(|e| WireguardError::config(format!("i{}: {e}", i + 1)))?;
            chains.extend(chain);
        }
        Ok(chains)
    }
}

// Ключ защиты заголовков не печатаем (`AGENTS.md` §5.2).
impl std::fmt::Debug for AmneziaParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut unsupported: Vec<&str> = self.unsupported.keys().map(String::as_str).collect();
        unsupported.sort_unstable();
        let signatures = [&self.i1, &self.i2, &self.i3, &self.i4, &self.i5]
            .iter()
            .filter(|spec| spec.is_some())
            .count();
        f.debug_struct("AmneziaParams")
            .field("jc", &self.jc)
            .field("jmin", &self.jmin)
            .field("jmax", &self.jmax)
            .field("s", &[self.s1, self.s2, self.s3, self.s4])
            .field("signatures", &signatures)
            .field(
                "header_protection_key",
                &self.header_protection_key.as_ref().map(|_| "<скрыт>"),
            )
            .field("content_padding_addition", &self.content_padding_addition)
            .field("random_trailers", &self.random_trailers)
            .field("unsupported", &unsupported)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// 32 байта 0x01 в base64.
    const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn parse(value: serde_json::Value) -> Result<AmneziaParams, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// Блок в духе премиум-сервера Amnezia: всё AWG 3 разом.
    fn awg3() -> serde_json::Value {
        json!({
            "jc": 3, "jmin": 40, "jmax": 70,
            "s1": 15, "s2": 18, "s3": 20, "s4": 23,
            "h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800",
            "i1": "<b 0xc700000001><r 16><t>",
            "i2": "<rc 8>",
            "header_protection_key": KEY,
            "content_padding_addition": "8-32",
            "random_trailers": true
        })
    }

    #[test]
    fn a_bare_block_defaults_to_standard_headers_and_no_junk() {
        let params = parse(json!({})).expect("разбирается");
        params.validate().expect("пустой блок допустим");
        let json = serde_json::to_value(&params).expect("сериализуется");
        assert_eq!(json["h1"], json!(1));
        assert_eq!(json["h4"], json!(4));
        assert_eq!(json["jc"], json!(0));
        assert!(
            json.get("random_trailers").is_none(),
            "выключенное не пишется"
        );
    }

    #[test]
    fn a_header_reads_both_as_a_number_and_as_a_range() {
        let params = parse(json!({ "h1": 12345, "h2": "100-200" })).expect("разбирается");
        params.validate().expect("верно");
        let json = serde_json::to_value(&params).expect("сериализуется");
        assert_eq!(json["h1"], json!(12345));
        assert_eq!(json["h2"], json!("100-200"));
    }

    #[test]
    fn a_reversed_range_is_refused() {
        assert!(parse(json!({ "h1": "200-100" })).is_err());
        assert!(parse(json!({ "content_padding_addition": "9-1" })).is_err());
    }

    #[test]
    fn a_full_awg_3_block_validates_and_survives_a_round_trip() {
        let params = parse(awg3()).expect("разбирается");
        params.validate().expect("AWG 3 поддержан");
        let back = serde_json::to_value(&params).expect("сериализуется");
        assert_eq!(back, awg3());
    }

    #[test]
    fn header_protection_needs_every_padding_to_hold_a_nonce() {
        let mut block = awg3();
        block["s3"] = json!(11);
        let error = parse(block)
            .expect("разбирается")
            .validate()
            .expect_err("S3 короче nonce");
        assert!(error.to_string().contains("S3"), "{error}");
    }

    #[test]
    fn a_header_protection_key_of_the_wrong_length_is_refused() {
        let mut block = awg3();
        block["header_protection_key"] = json!("AAAA");
        assert!(parse(block).expect("разбирается").validate().is_err());
    }

    #[test]
    fn an_all_zero_key_means_no_protection_and_needs_no_padding() {
        let params = parse(json!({
            "header_protection_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }))
        .expect("разбирается");
        params.validate().expect("нулевой ключ = защиты нет");
    }

    #[test]
    fn a_broken_signature_is_refused_by_its_number() {
        let error = parse(json!({ "i3": "<b 0x1>" }))
            .expect("разбирается")
            .validate()
            .expect_err("нечётный hex");
        assert!(error.to_string().contains("i3"), "{error}");
    }

    #[test]
    fn awg_3_timers_are_refused_by_name() {
        let params = parse(json!({ "jc": 3, "jmin": 40, "jmax": 70, "rekey_after_time": "100" }))
            .expect("разбирается: лишние поля собираются, а не падают");
        let error = params.validate().expect_err("таймеры не поддержаны");
        assert!(error.to_string().contains("rekey_after_time"), "{error}");
    }

    #[test]
    fn the_header_protection_key_never_shows_up_in_the_log() {
        let params = parse(awg3()).expect("разбирается");
        let shown = format!("{params:?}");
        assert!(!shown.contains(KEY), "{shown}");
        assert!(shown.contains("header_protection_key"), "{shown}");
    }

    #[test]
    fn junk_with_max_below_min_is_refused() {
        let params = parse(json!({ "jc": 2, "jmin": 70, "jmax": 40 })).expect("разбирается");
        assert!(params.validate().is_err());
    }

    #[test]
    fn junk_bounds_are_not_checked_when_no_junk_is_sent() {
        let params = parse(json!({ "jc": 0, "jmin": 70, "jmax": 40 })).expect("разбирается");
        params.validate().expect("без junk границы не важны");
    }
}
