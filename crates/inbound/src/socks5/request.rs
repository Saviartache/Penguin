//! Запрос CONNECT/BIND/ASSOCIATE и ответ на него.
//!
//! ```text
//! клиент → 0x05 CMD 0x00 ATYP АДРЕС ПОРТ
//! сервер → 0x05 REP 0x00 ATYP АДРЕС ПОРТ
//! ```
//!
//! Ответ уходит после настоящей попытки соединения: его код видит пользователь.

use std::net::{Ipv4Addr, SocketAddr};

use bytes::BufMut;
use penguin_core::address::SocketAddress;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::address;
use super::handshake::VERSION;
use crate::error::{InboundError, InboundResult};

/// Установить соединение.
pub const CMD_CONNECT: u8 = 0x01;
/// Принять входящее соединение. Не поддерживается.
pub const CMD_BIND: u8 = 0x02;
/// Открыть канал для UDP.
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// Всё получилось.
pub const REP_SUCCESS: u8 = 0x00;

/// Самый длинный ответ: заголовок 3 + ATYP 1 + IPv6 16 + порт 2.
const REPLY_MAX: usize = 22;

/// Что попросил клиент.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Соединиться с адресом.
    Connect(SocketAddress),
    /// Открыть канал для UDP; адрес — откуда клиент будет слать, нули — «не знаю».
    UdpAssociate(SocketAddress),
}

/// Читает запрос.
pub async fn read<S>(stream: &mut S) -> InboundResult<Command>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let [version, command, _reserved, atyp] = head;
    if version != VERSION {
        return Err(InboundError::NotSocks5(version));
    }
    let address = address::read_after_type(stream, atyp).await?;

    match command {
        CMD_CONNECT => Ok(Command::Connect(address)),
        CMD_UDP_ASSOCIATE => Ok(Command::UdpAssociate(address)),
        other => Err(InboundError::UnsupportedCommand(other)),
    }
}

/// Отправляет успешный ответ с указанным адресом.
pub async fn reply_success<S>(stream: &mut S, bound: SocketAddr) -> InboundResult<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    reply(stream, REP_SUCCESS, bound).await
}

/// Отправляет отказ с нулевым адресом: соединения нет.
pub async fn reply_failure<S>(stream: &mut S, code: u8) -> InboundResult<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    reply(stream, code, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).await
}

async fn reply<S>(stream: &mut S, code: u8, bound: SocketAddr) -> InboundResult<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = [0u8; REPLY_MAX];
    let mut cursor = &mut buf[..];
    cursor.put_slice(&[VERSION, code, 0x00]);
    address::encode_socket_addr(bound, &mut cursor);
    let len = REPLY_MAX - cursor.len();
    stream.write_all(&buf[..len]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use tokio::io::duplex;

    use super::*;

    fn connect_request(host: &str, port: u16) -> Vec<u8> {
        let mut out = vec![VERSION, CMD_CONNECT, 0x00];
        let mut buf = BytesMut::new();
        address::encode(&SocketAddress::domain(host, port), &mut buf);
        out.extend_from_slice(&buf);
        out
    }

    #[tokio::test]
    async fn reads_connect() {
        let mut reader = std::io::Cursor::new(connect_request("example.com", 443));
        let command = read(&mut reader).await.expect("читается");
        assert_eq!(
            command,
            Command::Connect(SocketAddress::domain("example.com", 443))
        );
    }

    #[tokio::test]
    async fn rejects_bind() {
        let mut request = connect_request("example.com", 443);
        request[1] = CMD_BIND;
        let mut reader = std::io::Cursor::new(request);
        assert!(matches!(
            read(&mut reader).await,
            Err(InboundError::UnsupportedCommand(CMD_BIND))
        ));
    }

    #[tokio::test]
    async fn writes_success_reply() {
        let (mut ours, mut theirs) = duplex(1024);
        let bound: SocketAddr = "127.0.0.1:1080".parse().expect("адрес");
        reply_success(&mut ours, bound).await.expect("записано");

        let mut reply = vec![0u8; 10];
        theirs.read_exact(&mut reply).await.expect("прочитано");
        assert_eq!(reply[0], VERSION);
        assert_eq!(reply[1], REP_SUCCESS);
        let (decoded, _) = address::decode(&reply[3..]).expect("адрес разбирается");
        assert_eq!(decoded, SocketAddress::from(bound));
    }

    #[tokio::test]
    async fn writes_ipv6_reply_in_full() {
        let (mut ours, mut theirs) = duplex(1024);
        let bound: SocketAddr = "[::1]:1080".parse().expect("адрес");
        reply_success(&mut ours, bound).await.expect("записано");
        drop(ours);

        let mut reply = Vec::new();
        theirs.read_to_end(&mut reply).await.expect("прочитано");
        assert_eq!(reply.len(), REPLY_MAX);
    }

    #[tokio::test]
    async fn failure_reply_carries_the_code() {
        let (mut ours, mut theirs) = duplex(1024);
        reply_failure(&mut ours, 0x05).await.expect("записано");

        let mut reply = vec![0u8; 10];
        theirs.read_exact(&mut reply).await.expect("прочитано");
        assert_eq!(reply[1], 0x05);
    }

    #[test]
    fn error_codes_distinguish_causes() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            InboundError::UnsupportedCommand(CMD_BIND).socks5_reply(),
            0x07
        );
        assert_eq!(InboundError::UnsupportedAddressType(9).socks5_reply(), 0x08);
        assert_eq!(
            InboundError::Io(Error::from(ErrorKind::ConnectionRefused)).socks5_reply(),
            0x05
        );
    }
}
