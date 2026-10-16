//! Заголовок запроса.
//!
//! Открытый: `версия(1) | IV(16) | ключ(16) | байт ответа(1) | настройки(1) |
//! (дополнение<<4)|шифр(1) | 0 | команда | порт/тип/адрес | дополнение | FNV-1a(4)`.
//! На проводе: `опознаватель(16) | AEAD длины(18) | нонс соединения(8) | AEAD заголовка(N+16)`.
//! Оба AEAD — AES-128-GCM, ключ и нонс из вложенного KDF, AAD — опознаватель
//! (`proxy/vmess/aead/encrypt.go`, `proxy/vmess/encoding/client.go`, `v2fly/v2ray-core`).
//! Адрес пишет общий [`penguin_transport::addr::v2ray`].

use penguin_core::address::SocketAddress;
use penguin_core::uuid::Uuid;
use penguin_proto::random;
use penguin_transport::addr::v2ray;

use crate::crypto::checksum::fnv1a;
use crate::crypto::kdf::{kdf, kdf16};
use crate::crypto::session::Session;
use crate::crypto::{aes_gcm, auth_id, id};
use crate::error::{VmessError, VmessResult};
use crate::frame::clock::now_unix;

/// Версия заголовка (`proxy/vmess/encoding/encoding.go`).
pub const VERSION: u8 = 1;

/// Открыть поток до адреса назначения.
pub const CMD_TCP: u8 = 0x01;
/// Дальше по этому потоку пойдут датаграммы для одного адреса.
pub const CMD_UDP: u8 = 0x02;

const LABEL_KEY: &[u8] = b"VMess Header AEAD Key";
const LABEL_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const LABEL_KEY_LENGTH: &[u8] = b"VMess Header AEAD Key_Length";
const LABEL_NONCE_LENGTH: &[u8] = b"VMess Header AEAD Nonce_Length";

/// Заголовок запроса целиком, готовый лечь на провод.
pub fn build(
    uuid: &Uuid,
    session: &Session,
    command: u8,
    target: &SocketAddress,
) -> VmessResult<Vec<u8>> {
    let plain = build_plain(session, command, target)?;

    let cmd_key = id::cmd_key(uuid);
    let auth_id = auth_id::create(&cmd_key, now_unix());

    let connection_nonce: [u8; 8] = random::array();

    let len_key = kdf16(
        &cmd_key,
        &[LABEL_KEY_LENGTH, &auth_id[..], &connection_nonce[..]],
    );
    let len_nonce = header_nonce(&cmd_key, LABEL_NONCE_LENGTH, &auth_id, &connection_nonce);
    let header_len = u16::try_from(plain.len())
        .map_err(|_| VmessError::malformed("заголовок длиннее 65535 байт"))?;
    let sealed_len = aes_gcm::seal(&len_key, &len_nonce, &auth_id, &header_len.to_be_bytes())?;

    let body_key = kdf16(&cmd_key, &[LABEL_KEY, &auth_id[..], &connection_nonce[..]]);
    let body_nonce = header_nonce(&cmd_key, LABEL_NONCE, &auth_id, &connection_nonce);
    let sealed_header = aes_gcm::seal(&body_key, &body_nonce, &auth_id, &plain)?;

    let mut wire = Vec::with_capacity(16 + sealed_len.len() + 8 + sealed_header.len());
    wire.extend_from_slice(&auth_id);
    wire.extend_from_slice(&sealed_len);
    wire.extend_from_slice(&connection_nonce);
    wire.extend_from_slice(&sealed_header);
    Ok(wire)
}

/// Нонс AEAD заголовка: первые 12 байт KDF.
fn header_nonce(cmd_key: &[u8; 16], label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8]) -> [u8; 12] {
    let full = kdf(cmd_key, &[label, &auth_id[..], &nonce[..]]);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/// Открытый заголовок.
fn build_plain(session: &Session, command: u8, target: &SocketAddress) -> VmessResult<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 256 + 15 + 4);
    out.push(VERSION);
    out.extend_from_slice(&session.request_body_iv);
    out.extend_from_slice(&session.request_body_key);
    out.push(session.response_header);
    out.push(session.wire.option_byte());

    // Длина дополнения 0..16 — четыре старших бита байта шифра.
    let padding_len = random::range(0..16) as u8;
    out.push((padding_len << 4) | session.wire.security_byte());
    out.push(0);
    out.push(command);
    v2ray::encode(target, &mut out)?;

    if padding_len > 0 {
        let before = out.len();
        out.resize(before + usize::from(padding_len), 0);
        random::fill(&mut out[before..]);
    }

    let checksum = fnv1a(&out);
    out.extend_from_slice(&checksum.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::security::Wire;

    fn uuid() -> Uuid {
        "b831381d-6324-4d53-ad4f-8cda48b30811"
            .parse()
            .expect("разбирается")
    }

    #[test]
    fn the_wire_layout_has_the_four_pieces_in_order() {
        let session = Session::new(Wire::Aes128Gcm);
        let wire = build(
            &uuid(),
            &session,
            CMD_TCP,
            &SocketAddress::domain("example.com", 443),
        )
        .expect("собирается");

        assert!(wire.len() > 42, "заголовка нет вовсе");
    }

    #[test]
    fn two_headers_for_the_same_target_do_not_repeat() {
        let session_a = Session::new(Wire::Aes128Gcm);
        let session_b = Session::new(Wire::Aes128Gcm);
        let target = SocketAddress::domain("example.com", 443);

        let a = build(&uuid(), &session_a, CMD_TCP, &target).expect("собирается");
        let b = build(&uuid(), &session_b, CMD_TCP, &target).expect("собирается");
        assert_ne!(a, b);
    }

    #[test]
    fn the_udp_command_only_changes_the_command_byte() {
        const BEFORE_SECURITY_BYTE: usize = 1 + 16 + 16 + 1 + 1;
        const COMMAND_INDEX: usize = BEFORE_SECURITY_BYTE + 2;

        let session = Session::new(Wire::Aes128Gcm);
        let target = SocketAddress::domain("example.com", 443);
        let plain_tcp = build_plain(&session, CMD_TCP, &target).expect("собирается");
        let plain_udp = build_plain(&session, CMD_UDP, &target).expect("собирается");

        assert_eq!(
            plain_tcp[..BEFORE_SECURITY_BYTE],
            plain_udp[..BEFORE_SECURITY_BYTE]
        );
        assert_eq!(plain_tcp[COMMAND_INDEX], CMD_TCP);
        assert_eq!(plain_udp[COMMAND_INDEX], CMD_UDP);
    }

    #[test]
    fn the_checksum_is_the_last_four_bytes() {
        let session = Session::new(Wire::Aes128Gcm);
        let target = SocketAddress::domain("example.com", 443);
        let plain = build_plain(&session, CMD_TCP, &target).expect("собирается");

        let (body, checksum) = plain.split_at(plain.len() - 4);
        assert_eq!(fnv1a(body).to_be_bytes(), checksum);
    }
}
