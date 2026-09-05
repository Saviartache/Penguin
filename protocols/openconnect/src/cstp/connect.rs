//! `CONNECT`: второе TLS-соединение, поднимающее сам тоннель CSTP.
//!
//! Заголовки запроса и их порядок — из `openconnect/cstp.c`
//! (`start_cstp_connection`); заголовки ответа — из `ocserv/src/worker-vpn.c`
//! (`connect_handler`). Из полного набора здесь послано и разобрано только
//! то, что нужно клиенту без сжатия и без DTLS (см. документ крейта):
//! компрессия, подсказки для переподключения и заголовки `X-DTLS-*` не
//! посылаются вовсе — без них сервер их и не предложит.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use penguin_core::address::Address;
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use penguin_proto::stream::ProxyStream;
use penguin_transport::deadline;
use penguin_transport::tls::TlsClient;
use tokio::io::AsyncWriteExt;

use crate::auth::{COOKIE_NAME, USER_AGENT};
use crate::error::{OpenConnectError, OpenConnectResult};
use crate::head::{self, Head};

/// Путь запроса `CONNECT`. Буквальная строка из `cstp.c`, а не производная от
/// адреса или пути входа: `ocserv` (`worker-vpn.c`) сверяет её через
/// `strcmp` и отвечает `404` на любую другую.
pub const PATH: &str = "/CSCOSSLC/tunnel";

/// `X-CSTP-Base-MTU`, который называем в запросе.
///
/// Не измеряется: путь до сервера идёт через сокет, который выдаёт
/// [`Dialer`], а он не открывает доступа к `TCP_INFO`/`TCP_MAXSEG` — тому,
/// чем сам `openconnect` меряет реальный MTU пути. Значение — тот же откат,
/// которым `cstp.c` пользуется, когда измерить не вышло: 1406 при базовом
/// Ethernet-MTU 1500. Итоговый MTU тоннеля в любом случае берётся из ответа
/// сервера ([`Params::mtu`]), а не из этого числа.
pub const REQUEST_BASE_MTU: u16 = 1406;

/// Имя в заголовке `X-CSTP-Hostname`.
///
/// Настоящее имя устройства туда не идёт: `ocserv` использует его только для
/// своего журнала (`worker-vpn.c`), а называть внешнему серверу имя машины
/// ради строки в чужом логе незачем.
const LOCAL_HOSTNAME: &str = "penguin";

/// Что сервер назвал про интерфейс тоннеля и его сроки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// Адрес IPv4 и длина префикса — из `X-CSTP-Address`/`X-CSTP-Netmask`.
    pub ipv4: (Ipv4Addr, u8),
    /// Адрес IPv6, если сервер его выдал.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// MTU тоннеля.
    pub mtu: u16,
    /// `X-CSTP-Keepalive`. Не задан — сервер не просил поддерживающих кадров.
    pub keepalive: Option<Duration>,
    /// `X-CSTP-DPD`. Не задан — сервер не просил проверки живости.
    pub dpd: Option<Duration>,
    /// Серверы имён из `X-CSTP-DNS`, в порядке прихода.
    ///
    /// Их надо брать именно у сервера: внутри тоннеля часто своё пространство
    /// имён, и чужой сервер имён про него не знает.
    pub dns: Vec<IpAddr>,
}

/// Открывает тоннель: новое TLS-соединение, запрос `CONNECT`, разбор ответа.
///
/// Соединение отдельное от входа (см. документ [`crate::auth`]) — так делает
/// сам `openconnect` (`cstp.c: cstp_connect` заново зовёт `openconnect_open_https`).
/// Кука, добытая на входе, — единственное, что переходит с одного соединения
/// на другое.
pub async fn open(
    dialer: &dyn Dialer,
    tls: &TlsClient,
    host: &Address,
    port: u16,
    host_header: &str,
    cookie: &str,
) -> OpenConnectResult<(Box<dyn ProxyStream>, Vec<u8>, Params)> {
    deadline::handshake("CONNECT OpenConnect", async {
        let plain = connect::dial(dialer, host, port)
            .await
            .map_err(|e| OpenConnectError::disconnected(e.to_string()))?;
        let mut secure = tls.connect(plain).await?;

        let request = request_text(host_header, cookie);
        secure.write_all(request.as_bytes()).await?;
        secure.flush().await?;

        let (head, tail) = head::read(&mut secure).await?;
        check_status(&head)?;
        let params = parse_params(&head)?;

        Ok((Box::new(secure) as Box<dyn ProxyStream>, tail, params))
    })
    .await
}

/// Собирает текст запроса `CONNECT`.
fn request_text(host_header: &str, cookie: &str) -> String {
    format!(
        "CONNECT {PATH} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Cookie: {COOKIE_NAME}={cookie}\r\n\
         X-CSTP-Version: 1\r\n\
         X-CSTP-Hostname: {LOCAL_HOSTNAME}\r\n\
         X-CSTP-Base-MTU: {REQUEST_BASE_MTU}\r\n\
         X-CSTP-Address-Type: IPv6,IPv4\r\n\
         X-CSTP-Full-IPv6-Capability: true\r\n\r\n"
    )
}

/// Проверяет код ответа. Успех — ровно `200` (`cstp.c` сверяет по этому же
/// коду, текст пояснения — «CONNECTED» у `ocserv» — на разбор не влияет).
fn check_status(head: &Head) -> OpenConnectResult<()> {
    match head.status {
        200 => Ok(()),
        401 | 403 => Err(OpenConnectError::AuthRejected),
        status => {
            let reason = head
                .header("X-Reason")
                .map(|r| format!(": {r}"))
                .unwrap_or_default();
            Err(OpenConnectError::malformed(format!(
                "сервер ответил на CONNECT кодом {status}{reason}"
            )))
        }
    }
}

/// Разбирает заголовки ответа в параметры тоннеля.
fn parse_params(head: &Head) -> OpenConnectResult<Params> {
    Ok(Params {
        ipv4: parse_ipv4(head)?,
        ipv6: parse_ipv6(head)?,
        mtu: parse_mtu(head)?,
        keepalive: parse_seconds(head, "X-CSTP-Keepalive")?,
        dpd: parse_seconds(head, "X-CSTP-DPD")?,
        dns: parse_dns(head),
    })
}

/// Серверы имён из `X-CSTP-DNS`.
///
/// Заголовок повторяется по разу на сервер (`worker-vpn.c`), а не собирает
/// их в одну строку. Неразборчивое значение пропускается, а не роняет вход:
/// тоннель без сервера имён работает, просто без доменных имён.
fn parse_dns(head: &Head) -> Vec<IpAddr> {
    head.headers_named("X-CSTP-DNS")
        .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        .collect()
}

/// Адрес IPv4 и его префикс. Обязателен: [`penguin_proto::packet::PacketInterface::ipv4`]
/// не `Option`, и развёртывание `ocserv` без пула IPv4 контракт не поддержан.
fn parse_ipv4(head: &Head) -> OpenConnectResult<(Ipv4Addr, u8)> {
    let address = head
        .headers_named("X-CSTP-Address")
        .find(|value| !value.contains(':'))
        .ok_or_else(|| {
            OpenConnectError::malformed(
                "сервер не назвал адрес IPv4 (`X-CSTP-Address`): направлению \
                 уровня пакетов он нужен всегда",
            )
        })?;
    let ip: Ipv4Addr = address
        .parse()
        .map_err(|_| OpenConnectError::malformed(format!("`X-CSTP-Address: {address}` не IPv4")))?;

    let mask = head
        .headers_named("X-CSTP-Netmask")
        .find(|value| !value.contains(':') && !value.contains('/'))
        .ok_or_else(|| {
            OpenConnectError::malformed("сервер не назвал маску (`X-CSTP-Netmask`) для адреса IPv4")
        })?;
    let mask: Ipv4Addr = mask.parse().map_err(|_| {
        OpenConnectError::malformed(format!("`X-CSTP-Netmask: {mask}` не разбирается"))
    })?;

    Ok((ip, netmask_to_prefix(mask)?))
}

/// Длина префикса, если маска — непрерывный ряд единиц с начала.
fn netmask_to_prefix(mask: Ipv4Addr) -> OpenConnectResult<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    let reconstructed = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    if bits != reconstructed {
        return Err(OpenConnectError::malformed(format!(
            "маска `{mask}` не сплошная: такую нельзя записать длиной префикса"
        )));
    }
    Ok(ones as u8)
}

/// Адрес IPv6 и префикс, если сервер его выдал.
///
/// Два формата, оба из `cstp.c`: полный режим — отдельным заголовком
/// `X-CSTP-Address-IP6: addr/prefix`; устаревший — тем же `X-CSTP-Address`,
/// что и IPv4 (отличается наличием `:`), с длиной префикса в
/// `X-CSTP-Netmask` в виде `net/prefix`.
fn parse_ipv6(head: &Head) -> OpenConnectResult<Option<(Ipv6Addr, u8)>> {
    if let Some(combined) = head.header("X-CSTP-Address-IP6") {
        return Ok(Some(split_ip6_prefix(combined)?));
    }

    let Some(address) = head
        .headers_named("X-CSTP-Address")
        .find(|v| v.contains(':'))
    else {
        return Ok(None);
    };
    let ip: Ipv6Addr = address
        .parse()
        .map_err(|_| OpenConnectError::malformed(format!("`X-CSTP-Address: {address}` не IPv6")))?;
    let mask = head
        .headers_named("X-CSTP-Netmask")
        .find(|v| v.contains('/'))
        .ok_or_else(|| {
            OpenConnectError::malformed(
                "сервер выдал IPv6-адрес без длины префикса (`X-CSTP-Netmask`)",
            )
        })?;
    let (_, prefix) = mask
        .split_once('/')
        .ok_or_else(|| OpenConnectError::malformed(format!("`X-CSTP-Netmask: {mask}` без `/`")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| OpenConnectError::malformed(format!("длина префикса `{prefix}` не число")))?;
    Ok(Some((ip, prefix)))
}

/// Делит `addr/prefix` на составляющие.
fn split_ip6_prefix(value: &str) -> OpenConnectResult<(Ipv6Addr, u8)> {
    let (addr, prefix) = value.split_once('/').ok_or_else(|| {
        OpenConnectError::malformed(format!("`X-CSTP-Address-IP6: {value}` без `/`"))
    })?;
    let ip: Ipv6Addr = addr.parse().map_err(|_| {
        OpenConnectError::malformed(format!("`X-CSTP-Address-IP6: {value}` не IPv6"))
    })?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| OpenConnectError::malformed(format!("длина префикса `{prefix}` не число")))?;
    Ok((ip, prefix))
}

/// MTU тоннеля: `X-CSTP-MTU`, а если сервер прислал только базовый — он.
fn parse_mtu(head: &Head) -> OpenConnectResult<u16> {
    let raw = head
        .header("X-CSTP-MTU")
        .or_else(|| head.header("X-CSTP-Base-MTU"))
        .ok_or_else(|| {
            OpenConnectError::malformed("сервер не назвал MTU (`X-CSTP-MTU`/`X-CSTP-Base-MTU`)")
        })?;
    raw.trim()
        .parse()
        .map_err(|_| OpenConnectError::malformed(format!("MTU `{raw}` не число")))
}

/// Секунды из именованного заголовка. Заголовка нет — значит выключено, а не
/// ноль: `X-CSTP-Keepalive`/`X-CSTP-DPD` сервер посылает, только когда они
/// действительно включены (`worker-vpn.c`).
fn parse_seconds(head: &Head, name: &str) -> OpenConnectResult<Option<Duration>> {
    match head.header(name) {
        None => Ok(None),
        Some(raw) => raw
            .trim()
            .parse()
            .map(Duration::from_secs)
            .map(Some)
            .map_err(|_| OpenConnectError::malformed(format!("`{name}: {raw}` не число"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(pairs: Vec<(&str, &str)>) -> Head {
        Head {
            status: 200,
            headers: pairs
                .into_iter()
                .map(|(n, v)| (n.to_owned(), v.to_owned()))
                .collect(),
        }
    }

    #[test]
    fn the_request_line_is_the_literal_ocserv_expects() {
        let text = request_text("vpn.example.com", "deadbeef");
        assert!(
            text.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"),
            "{text}"
        );
        assert!(text.contains("Cookie: webvpn=deadbeef\r\n"), "{text}");
        assert!(
            text.contains("X-CSTP-Full-IPv6-Capability: true\r\n"),
            "{text}"
        );
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_plain_ipv4_response_is_understood() {
        let head = head(vec![
            ("X-CSTP-Address", "10.7.0.2"),
            ("X-CSTP-Netmask", "255.255.255.0"),
            ("X-CSTP-MTU", "1400"),
            ("X-CSTP-Keepalive", "30"),
            ("X-CSTP-DPD", "60"),
        ]);
        let params = parse_params(&head).expect("разбирается");
        assert_eq!(params.ipv4, (Ipv4Addr::new(10, 7, 0, 2), 24));
        assert_eq!(params.ipv6, None);
        assert_eq!(params.mtu, 1400);
        assert_eq!(params.keepalive, Some(Duration::from_secs(30)));
        assert_eq!(params.dpd, Some(Duration::from_secs(60)));
    }

    #[test]
    fn missing_timers_mean_disabled_not_zero() {
        let head = head(vec![
            ("X-CSTP-Address", "10.7.0.2"),
            ("X-CSTP-Netmask", "255.255.255.255"),
            ("X-CSTP-MTU", "1400"),
        ]);
        let params = parse_params(&head).expect("разбирается");
        assert_eq!(params.keepalive, None);
        assert_eq!(params.dpd, None);
    }

    #[test]
    fn full_ipv6_mode_uses_the_dedicated_header() {
        let head = head(vec![
            ("X-CSTP-Address", "10.7.0.2"),
            ("X-CSTP-Netmask", "255.255.255.0"),
            ("X-CSTP-Address-IP6", "2001:db8::2/64"),
            ("X-CSTP-Base-MTU", "1406"),
        ]);
        let params = parse_params(&head).expect("разбирается");
        assert_eq!(
            params.ipv6,
            Some(("2001:db8::2".parse().expect("адрес"), 64))
        );
    }

    #[test]
    fn legacy_ipv6_mode_reuses_address_and_netmask() {
        // Тот же `X-CSTP-Address`, что и у IPv4, — только со значением IPv6 —
        // и длина префикса в `X-CSTP-Netmask` через `/` (`cstp.c`).
        let head = head(vec![
            ("X-CSTP-Address", "10.7.0.2"),
            ("X-CSTP-Netmask", "255.255.255.0"),
            ("X-CSTP-Address", "2001:db8::2"),
            ("X-CSTP-Netmask", "2001:db8::/64"),
            ("X-CSTP-MTU", "1400"),
        ]);
        let params = parse_params(&head).expect("разбирается");
        assert_eq!(
            params.ipv6,
            Some(("2001:db8::2".parse().expect("адрес"), 64))
        );
    }

    #[test]
    fn a_missing_ipv4_address_is_an_error_not_a_zero_address() {
        let head = head(vec![("X-CSTP-MTU", "1400")]);
        let err = parse_params(&head).expect_err("нет IPv4");
        assert!(err.to_string().contains("IPv4"), "{err}");
    }

    #[test]
    fn a_discontinuous_netmask_is_refused() {
        let mask = Ipv4Addr::new(255, 0, 255, 0);
        assert!(netmask_to_prefix(mask).is_err());
    }

    #[test]
    fn every_prefix_length_round_trips_through_a_mask() {
        for prefix in 0u8..=32 {
            let bits = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let mask = Ipv4Addr::from(bits);
            assert_eq!(netmask_to_prefix(mask).expect("сплошная маска"), prefix);
        }
    }

    #[test]
    fn a_401_on_connect_is_an_auth_rejection() {
        // Кука истекла или подделана — тот же смысл, что неверный пароль на
        // входе: повторять тем же значением бессмысленно.
        let head = Head {
            status: 401,
            headers: Vec::new(),
        };
        assert!(matches!(
            check_status(&head),
            Err(OpenConnectError::AuthRejected)
        ));
    }

    #[test]
    fn an_unexpected_status_names_the_code_and_the_reason() {
        let head = Head {
            status: 503,
            headers: vec![("X-Reason".to_owned(), "busy".to_owned())],
        };
        let err = check_status(&head).expect_err("не 200");
        assert!(err.to_string().contains("503"), "{err}");
        assert!(err.to_string().contains("busy"), "{err}");
    }
}
