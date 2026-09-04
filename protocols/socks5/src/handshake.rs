//! Разговор с прокси до того, как по соединению пойдут данные приложения.
//!
//! Три шага, и все три обязательны в этом порядке (RFC 1928, §3–4):
//!
//! ```text
//!  клиент ──► приветствие: какие способы проверки я умею
//!  прокси ──► выбранный способ
//!  клиент ──► имя и пароль            ─┐ только если выбран способ 2
//!  прокси ──► принято или нет         ─┘        (RFC 1929)
//!  клиент ──► команда и адрес назначения
//!  прокси ──► ответ и адрес, которым он представился
//! ```
//!
//! Сборка байт вынесена в свободные функции без `tokio` — их видно целиком и
//! можно проверить без сети. Ждать умеют только [`negotiate`] и [`command`].

use penguin_core::address::SocketAddress;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use penguin_transport::addr::socks::{self as address, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

use crate::error::{Socks5Error, Socks5Result};

/// Версия протокола.
pub const VERSION: u8 = 0x05;

/// Способ проверки подлинности: никакой.
pub const METHOD_NONE: u8 = 0x00;
/// Способ проверки подлинности: имя и пароль (RFC 1929).
pub const METHOD_USERPASS: u8 = 0x02;
/// Ответ прокси «ни один из предложенных способов не подходит».
pub const METHOD_UNACCEPTABLE: u8 = 0xFF;

/// Версия обмена именем и паролем. Своя, не совпадает с версией протокола.
pub const AUTH_VERSION: u8 = 0x01;

/// Открыть поток до адреса назначения.
pub const CMD_CONNECT: u8 = 0x01;
/// Попросить канал для датаграмм.
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// Приветствие: перечень способов, которыми клиент умеет представиться.
///
/// «Никакой» предлагается всегда, даже когда пароль задан: прокси, который
/// его не спрашивает, иначе получил бы список, из которого ему нечего выбрать.
pub fn greeting(with_credentials: bool) -> Vec<u8> {
    if with_credentials {
        vec![VERSION, 2, METHOD_NONE, METHOD_USERPASS]
    } else {
        vec![VERSION, 1, METHOD_NONE]
    }
}

/// Имя и пароль в записи RFC 1929.
///
/// Длина каждого поля — один байт; всё, что длиннее 255 байт, обрезается ещё
/// в [`crate::config::Socks5Config::validate`], до попытки подключения.
pub fn credentials_message(username: &str, password: &str) -> Socks5Result<Vec<u8>> {
    let user = username.as_bytes();
    let pass = password.as_bytes();
    let (Ok(user_len), Ok(pass_len)) = (u8::try_from(user.len()), u8::try_from(pass.len())) else {
        return Err(Socks5Error::config(
            "имя и пароль SOCKS5 не длиннее 255 байт каждый",
        ));
    };

    let mut out = Vec::with_capacity(3 + user.len() + pass.len());
    out.push(AUTH_VERSION);
    out.push(user_len);
    out.extend_from_slice(user);
    out.push(pass_len);
    out.extend_from_slice(pass);
    Ok(out)
}

/// Команда вместе с адресом, к которому она относится.
pub fn request(command: u8, target: &SocketAddress) -> Socks5Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + 259);
    out.push(VERSION);
    out.push(command);
    out.push(0); // резерв
    address::encode(target, &mut out)?;
    Ok(out)
}

/// Что означает код ответа прокси (RFC 1928, §6).
///
/// Свободная функция с таблицей, а не строка на месте: код `0x02` — это
/// «запрещено правилами прокси», и подпись «не удалось подключиться» на его
/// месте отправила бы человека чинить сеть вместо настроек прокси.
pub fn reason(code: u8) -> &'static str {
    match code {
        0x01 => "внутренняя ошибка прокси",
        0x02 => "запрещено правилами прокси",
        0x03 => "сеть недоступна",
        0x04 => "узел недостижим",
        0x05 => "соединение отклонено",
        0x06 => "истекло время жизни пакета",
        0x07 => "прокси не умеет такую команду",
        0x08 => "прокси не умеет такой тип адреса",
        _ => "прокси отказал без объяснения",
    }
}

/// Договаривается о способе проверки и, если нужно, проходит её.
///
/// После успешного возврата соединение готово принять команду.
pub async fn negotiate<S>(io: &mut S, credentials: Option<(&str, &str)>) -> Socks5Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(&greeting(credentials.is_some())).await?;
    io.flush().await?;

    let mut answer = [0u8; 2];
    io.read_exact(&mut answer).await?;
    if answer[0] != VERSION {
        return Err(Socks5Error::malformed(format!(
            "версия {:#04x} вместо 5",
            answer[0]
        )));
    }

    match answer[1] {
        METHOD_NONE => Ok(()),
        METHOD_USERPASS => match credentials {
            Some((username, password)) => authenticate(io, username, password).await,
            // Прокси выбрал способ, которого мы не предлагали. Считать это
            // сетевой ошибкой нельзя: пока пароль не задан, ответ будет тем же.
            None => Err(Socks5Error::AuthUnsupported),
        },
        METHOD_UNACCEPTABLE => Err(Socks5Error::AuthUnsupported),
        other => Err(Socks5Error::malformed(format!(
            "прокси выбрал неизвестный способ проверки {other:#04x}"
        ))),
    }
}

/// Предъявляет имя и пароль.
async fn authenticate<S>(io: &mut S, username: &str, password: &str) -> Socks5Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(&credentials_message(username, password)?)
        .await?;
    io.flush().await?;

    let mut answer = [0u8; 2];
    io.read_exact(&mut answer).await?;
    // Версия обмена своя: единица, а не пятёрка. Прокси, ответивший здесь
    // пятёркой, обычно и есть тот, кто «почти» реализует RFC 1929.
    if answer[0] != AUTH_VERSION {
        return Err(Socks5Error::malformed(format!(
            "проверка подлинности версии {:#04x} вместо 1",
            answer[0]
        )));
    }
    if answer[1] != 0 {
        return Err(Socks5Error::AuthRejected);
    }
    Ok(())
}

/// Отправляет команду и читает ответ.
///
/// Возвращает адрес, которым представился прокси: для [`CMD_CONNECT`] он мало
/// что значит, а для [`CMD_UDP_ASSOCIATE`] это и есть тот адрес, на который
/// потом уходят датаграммы.
pub async fn command<S>(
    io: &mut S,
    command: u8,
    target: &SocketAddress,
) -> Socks5Result<SocketAddress>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(&request(command, target)?).await?;
    io.flush().await?;

    let mut head = [0u8; 4];
    io.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(Socks5Error::malformed(format!(
            "версия {:#04x} вместо 5",
            head[0]
        )));
    }
    if head[1] != 0 {
        return Err(Socks5Error::Refused {
            target: target.to_wire(),
            reason: reason(head[1]),
        });
    }

    read_address(io, head[3]).await
}

/// Дочитывает адрес, тип которого уже известен.
///
/// Читается ровно столько, сколько обещает тип: лишний байт из потока — это
/// первый байт данных приложения, и забрать его значило бы испортить
/// соединение молча.
async fn read_address<S>(io: &mut S, atyp: u8) -> Socks5Result<SocketAddress>
where
    S: AsyncRead + Unpin,
{
    let mut frame = Vec::with_capacity(1 + 259);
    frame.push(atyp);

    match atyp {
        // Хвост — сам адрес плюс два байта порта.
        ATYP_IPV4 => read_into(io, &mut frame, 4 + 2).await?,
        ATYP_IPV6 => read_into(io, &mut frame, 16 + 2).await?,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            io.read_exact(&mut len).await?;
            frame.push(len[0]);
            read_into(io, &mut frame, usize::from(len[0]) + 2).await?;
        }
        other => {
            return Err(Socks5Error::malformed(format!(
                "неизвестный тип адреса {other:#04x}"
            )));
        }
    }

    address::decode(&frame)?
        .map(|(addr, _)| addr)
        .ok_or_else(|| Socks5Error::malformed("адрес в ответе оборвался"))
}

/// Дочитывает ровно `count` байт в конец буфера.
async fn read_into<S>(io: &mut S, buffer: &mut Vec<u8>, count: usize) -> Socks5Result<()>
where
    S: AsyncRead + Unpin,
{
    let start = buffer.len();
    buffer.resize(start + count, 0);
    io.read_exact(&mut buffer[start..]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    /// Соединение с поддельным прокси, отвечающим заранее записанным.
    ///
    /// Настоящего сокета здесь нет: разговор с прокси — это байты, и проверять
    /// его надо байтами, а не поднятым сервером.
    async fn proxy(script: &[u8]) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        let (client, mut server) = duplex(4096);
        server.write_all(script).await.expect("сценарий пишется");
        (client, server)
    }

    #[test]
    fn the_greeting_always_offers_the_way_without_a_password() {
        // Прокси, который пароля не спрашивает, иначе получил бы список, из
        // которого ему нечего выбрать.
        assert_eq!(greeting(false), vec![5, 1, 0]);
        assert_eq!(greeting(true), vec![5, 2, 0, 2]);
    }

    #[test]
    fn credentials_are_laid_out_by_the_rfc() {
        let message = credentials_message("пингвин", "").expect("собирается");
        assert_eq!(message[0], AUTH_VERSION);
        assert_eq!(usize::from(message[1]), "пингвин".len());
        // Пустой пароль — это длина ноль, а не отсутствие поля.
        assert_eq!(*message.last().expect("есть"), 0);
    }

    #[test]
    fn a_request_carries_the_name_not_the_address() {
        let bytes =
            request(CMD_CONNECT, &SocketAddress::domain("example.com", 443)).expect("собирается");
        assert_eq!(&bytes[..3], &[VERSION, CMD_CONNECT, 0]);
        assert_eq!(bytes[3], ATYP_DOMAIN);
    }

    #[test]
    fn every_reply_code_says_something_useful() {
        // «Запрещено правилами прокси» отправляет чинить настройки, а
        // «не удалось подключиться» — чинить сеть. Это разные вечера.
        for code in 1..=8u8 {
            assert!(!reason(code).is_empty());
        }
        assert_ne!(reason(0x02), reason(0x05));
    }

    #[tokio::test]
    async fn a_proxy_without_a_password_lets_us_through() {
        let (mut client, _server) = proxy(&[VERSION, METHOD_NONE]).await;
        negotiate(&mut client, None).await.expect("пропустил");
    }

    #[tokio::test]
    async fn a_password_is_offered_and_accepted() {
        let (mut client, _server) = proxy(&[VERSION, METHOD_USERPASS, AUTH_VERSION, 0]).await;
        negotiate(&mut client, Some(("penguin", "secret")))
            .await
            .expect("пропустил");
    }

    #[tokio::test]
    async fn a_wrong_password_is_told_apart_from_a_broken_link() {
        // От этого зависит, будет ли `supervisor` повторять попытку.
        let (mut client, _server) = proxy(&[VERSION, METHOD_USERPASS, AUTH_VERSION, 1]).await;
        let err = negotiate(&mut client, Some(("penguin", "secret")))
            .await
            .expect_err("пароль неверен");
        assert!(matches!(err, Socks5Error::AuthRejected));
    }

    #[tokio::test]
    async fn a_proxy_that_wants_a_password_we_do_not_have_says_so() {
        let (mut client, _server) = proxy(&[VERSION, METHOD_UNACCEPTABLE]).await;
        let err = negotiate(&mut client, None).await.expect_err("не пустил");
        assert!(matches!(err, Socks5Error::AuthUnsupported));
    }

    #[tokio::test]
    async fn the_wrong_kind_of_proxy_is_recognised_at_once() {
        // На порту сидит HTTP-прокси: он отвечает текстом, а не пятёркой.
        let (mut client, _server) = proxy(b"HTTP/1.1 400 Bad Request\r\n").await;
        let err = negotiate(&mut client, None).await.expect_err("не SOCKS5");
        assert!(matches!(err, Socks5Error::Malformed(_)));
    }

    #[tokio::test]
    async fn a_connect_reply_carries_the_bound_address() {
        let script = [VERSION, 0, 0, ATYP_IPV4, 203, 0, 113, 5, 0x04, 0x38];
        let (mut client, _server) = proxy(&script).await;

        let bound = command(
            &mut client,
            CMD_CONNECT,
            &SocketAddress::domain("example.com", 443),
        )
        .await
        .expect("прокси согласился");

        assert_eq!(bound.to_wire(), "203.0.113.5:1080");
    }

    #[tokio::test]
    async fn a_bound_address_can_be_a_name_too() {
        // Прокси вправе представиться именем; читать надо ровно столько, сколько
        // он обещал, иначе следующий байт — это уже данные приложения.
        let mut script = vec![VERSION, 0, 0, ATYP_DOMAIN, 11];
        script.extend_from_slice(b"example.net");
        script.extend_from_slice(&443u16.to_be_bytes());
        let (mut client, _server) = proxy(&script).await;

        let bound = command(
            &mut client,
            CMD_UDP_ASSOCIATE,
            &SocketAddress::domain("example.com", 443),
        )
        .await
        .expect("прокси согласился");
        assert_eq!(bound.to_wire(), "example.net:443");
    }

    #[tokio::test]
    async fn a_refusal_names_the_target_and_the_reason() {
        let script = [VERSION, 0x02, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
        let (mut client, _server) = proxy(&script).await;

        let err = command(
            &mut client,
            CMD_CONNECT,
            &SocketAddress::domain("example.com", 443),
        )
        .await
        .expect_err("прокси отказал");

        let text = err.to_string();
        assert!(text.contains("example.com:443"), "нет адреса: {text}");
        assert!(text.contains("правилами"), "нет причины: {text}");
    }
}
