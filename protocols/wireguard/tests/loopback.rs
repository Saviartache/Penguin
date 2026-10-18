//! Направление против поддельного сервера — через настоящий сокет UDP.
//!
//! Проверяет `connect`, `send`/`recv` и `close` на настоящем сокете. Сервер -
//! роль ответчика по формулам спецификации поверх примитивов крейта.

#![allow(clippy::expect_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use penguin_core::address::SocketAddress;
use penguin_core::id::OutboundId;
use penguin_proto::dialer::Dialer;
use penguin_proto::error::ProtocolError;
use penguin_proto::packet::PacketOutbound;
use penguin_wireguard::config::WireguardConfig;
use penguin_wireguard::crypto::constants::{
    CONSTRUCTION, IDENTIFIER, INITIATION_MESSAGE_LEN, KEY_LEN, LABEL_MAC1, MESSAGE_INITIATION,
    MESSAGE_TRANSPORT_DATA, RESPONSE_MESSAGE_LEN,
};
use penguin_wireguard::crypto::primitives::{aead_open, aead_seal, hash, kdf2, kdf3, mac};
use penguin_wireguard::frame::{initiation, transport};
use penguin_wireguard::outbound::WireguardOutbound;
use tokio::net::{TcpStream, UdpSocket};
use x25519_dalek::{PublicKey, StaticSecret};

/// Предел ожидания события.
const PATIENCE: Duration = Duration::from_secs(5);

/// Звонящий, который ходит по настоящему сокету на loopback.
#[derive(Debug)]
struct LocalDialer;

#[async_trait::async_trait]
impl Dialer for LocalDialer {
    async fn dial_tcp(&self, _addr: SocketAddr) -> Result<TcpStream, ProtocolError> {
        Err(ProtocolError::Unsupported("TCP в этом тесте не нужен"))
    }

    async fn bind_udp(&self, local: SocketAddr) -> Result<UdpSocket, ProtocolError> {
        UdpSocket::bind(local)
            .await
            .map_err(|e| ProtocolError::Connect(e.to_string()))
    }

    async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, ProtocolError> {
        Err(ProtocolError::Unsupported(
            "имён в этом тесте нет — адрес сервера уже IP",
        ))
    }
}

/// Обфускация AmneziaWG со стороны теста: padding `S1`/`S2`/`S4`, магические
/// заголовки `H1`/`H2`/`H4`, а для AWG 3 — ключ защиты заголовков и хвост
/// после ответа. [`TestObf::NONE`] = обычный WireGuard.
#[derive(Clone, Copy)]
struct TestObf {
    s1: usize,
    s2: usize,
    s4: usize,
    h1: u32,
    h2: u32,
    h4: u32,
    key: Option<[u8; 32]>,
    response_trailer: usize,
}

impl TestObf {
    const NONE: Self = Self {
        s1: 0,
        s2: 0,
        s4: 0,
        h1: 1,
        h2: 2,
        h4: 4,
        key: None,
        response_trailer: 0,
    };

    /// Защита заголовков по `amneziawg-go`: ChaCha20 с nonce из первых 12 байт
    /// датаграммы поверх `datagram[start..end]`. Независимо от кода крейта.
    fn protect(&self, datagram: &mut [u8], start: usize, end: usize) {
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let Some(key) = self.key else { return };
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&datagram[..12]);
        ChaCha20::new(&key.into(), &nonce.into()).apply_keystream(&mut datagram[start..end]);
    }

    /// Случайный padding: с защитой он же nonce, поэтому не нули.
    fn padding(len: usize) -> Vec<u8> {
        let mut pad = vec![0u8; len];
        penguin_proto::random::fill(&mut pad);
        pad
    }
}

/// Наименьший IPv4-пакет с данными: только такое драйвер отдаёт наружу.
fn ip_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// Поддельный сервер: ответчик Noise IK, затем эхо пакетов данных.
struct FakeServer {
    socket: UdpSocket,
    private: StaticSecret,
    public: PublicKey,
    obf: TestObf,
}

impl FakeServer {
    async fn start() -> Self {
        Self::start_with_obf(TestObf::NONE).await
    }

    async fn start_with_obf(obf: TestObf) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("слушается");
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);
        Self {
            socket,
            private,
            public,
            obf,
        }
    }

    /// Снимает `S4` и защиту, проверяет `H4` и возвращает стандартный тип 4 для разбора.
    fn deobfuscate_transport(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        let s4 = self.obf.s4;
        if datagram.len() < s4 + 16 {
            return None;
        }
        let mut datagram = datagram.to_vec();
        self.obf.protect(&mut datagram, s4, s4 + 16);
        let header = u32::from_le_bytes(datagram[s4..s4 + 4].try_into().expect("4 байта"));
        if header != self.obf.h4 {
            return None;
        }
        let mut frame = datagram[s4..].to_vec();
        frame[0..4].copy_from_slice(&[MESSAGE_TRANSPORT_DATA, 0, 0, 0]);
        Some(frame)
    }

    /// Ставит заголовок `H4`, `S4` байт padding спереди и защиту заголовка.
    fn obfuscate_transport(&self, mut frame: Vec<u8>) -> Vec<u8> {
        frame[0..4].copy_from_slice(&self.obf.h4.to_le_bytes());
        let s4 = self.obf.s4;
        let mut out = TestObf::padding(s4);
        out.extend_from_slice(&frame);
        self.obf.protect(&mut out, s4, s4 + 16);
        out
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().expect("адрес")
    }

    fn public_base64(&self) -> String {
        penguin_core::base64::encode(self.public.as_bytes())
    }

    /// Одно рукопожатие (мы - ответчик); возвращает сеанс и датаграммы, пришедшие
    /// до инициации (сигнатуры `I1`–`I5` и junk).
    async fn perform_handshake(&self) -> (ServerSession, Vec<Vec<u8>>) {
        let mut buf = [0u8; 2048];
        let mut prelude = Vec::new();
        // Инициация - датаграмма не короче `S1` + 148 с `H1` под защитой; прочее - prelude.
        let frame_end = self.obf.s1 + INITIATION_MESSAGE_LEN;
        let (init_bytes, client_addr) = loop {
            let (len, addr) = self
                .socket
                .recv_from(&mut buf)
                .await
                .expect("датаграмма пришла");
            let mut datagram = buf[..len].to_vec();
            if len >= frame_end {
                self.obf.protect(&mut datagram, self.obf.s1, frame_end);
                if datagram[self.obf.s1..self.obf.s1 + 4] == self.obf.h1.to_le_bytes() {
                    break (datagram[self.obf.s1..frame_end].to_vec(), addr);
                }
            }
            prelude.push(buf[..len].to_vec());
        };
        self.socket
            .connect(client_addr)
            .await
            .expect("подключение к клиенту");

        // Клиент поставил заголовок `H1` вместо типа 1.
        let header =
            u32::from_le_bytes([init_bytes[0], init_bytes[1], init_bytes[2], init_bytes[3]]);
        assert_eq!(header, self.obf.h1, "магический заголовок инициации H1");

        // mac1 инициации посчитан поверх этого заголовка - проверяем это.
        let init_mac1_key = hash(&[LABEL_MAC1, self.public.as_bytes()]);
        assert_eq!(
            &mac(&init_mac1_key, &init_bytes[..116])[..],
            &init_bytes[116..132],
            "mac1 инициации сошёлся на магическом заголовке"
        );

        // Возвращаем стандартный тип, чтобы разобрать поля по смещениям.
        let mut restored = init_bytes;
        restored[0] = MESSAGE_INITIATION;
        let init = initiation::parse(&restored).expect("инициация разбирается");

        // Шаги 1-2: хэш замешивает свой статический ключ.
        let mut chaining_key = hash(&[CONSTRUCTION]);
        let mut transcript = hash(&[&chaining_key, IDENTIFIER]);
        transcript = hash(&[&transcript, self.public.as_bytes()]);

        // Шаг 3: эфемерный ключ инициатора.
        chaining_key =
            penguin_wireguard::crypto::primitives::kdf1(&chaining_key, &init.ephemeral_public);
        transcript = hash(&[&transcript, &init.ephemeral_public]);

        // Шаг 4: расшифровать статический ключ инициатора.
        let ss = *self
            .private
            .diffie_hellman(&PublicKey::from(init.ephemeral_public))
            .as_bytes();
        let (ck, key) = kdf2(&chaining_key, &ss);
        chaining_key = ck;
        let initiator_static = aead_open(&key, 0, &init.static_ciphertext, &transcript)
            .expect("статический ключ инициатора расшифровывается");
        transcript = hash(&[&transcript, &init.static_ciphertext]);

        let mut initiator_static_pub = [0u8; KEY_LEN];
        initiator_static_pub.copy_from_slice(&initiator_static);

        // Шаг 6: DH статика-статика.
        let ss_static = *self
            .private
            .diffie_hellman(&PublicKey::from(initiator_static_pub))
            .as_bytes();
        let (ck, key) = kdf2(&chaining_key, &ss_static);
        chaining_key = ck;
        let _timestamp = aead_open(&key, 0, &init.timestamp_ciphertext, &transcript)
            .expect("метка времени расшифровывается");
        transcript = hash(&[&transcript, &init.timestamp_ciphertext]);

        // Сообщение 2: свой эфемерный ключ, пустой PSK.
        let ephemeral_private = StaticSecret::random();
        let ephemeral_public = *PublicKey::from(&ephemeral_private).as_bytes();
        transcript = hash(&[&transcript, &ephemeral_public]);
        chaining_key =
            penguin_wireguard::crypto::primitives::kdf1(&chaining_key, &ephemeral_public);

        let ss_ee = *ephemeral_private
            .diffie_hellman(&PublicKey::from(init.ephemeral_public))
            .as_bytes();
        chaining_key = penguin_wireguard::crypto::primitives::kdf1(&chaining_key, &ss_ee);

        let ss_se = *ephemeral_private
            .diffie_hellman(&PublicKey::from(initiator_static_pub))
            .as_bytes();
        chaining_key = penguin_wireguard::crypto::primitives::kdf1(&chaining_key, &ss_se);

        let (chaining_key, tau, key) = kdf3(&chaining_key, &[0u8; KEY_LEN]);
        transcript = hash(&[&transcript, &tau]);

        let empty_ciphertext_vec = aead_seal(&key, 0, &[], &transcript);
        let mut empty_ciphertext = [0u8; 16];
        empty_ciphertext.copy_from_slice(&empty_ciphertext_vec);

        let server_local_index: u32 = 0xFEED_0001;
        let mut out = [0u8; RESPONSE_MESSAGE_LEN];
        // Магический заголовок `H2` вместо типа 2 (в обычном режиме это и есть 2).
        out[0..4].copy_from_slice(&self.obf.h2.to_le_bytes());
        out[4..8].copy_from_slice(&server_local_index.to_le_bytes());
        out[8..12].copy_from_slice(&init.sender_index.to_le_bytes());
        out[12..44].copy_from_slice(&ephemeral_public);
        out[44..60].copy_from_slice(&empty_ciphertext);
        let mac1_key = hash(&[LABEL_MAC1, &initiator_static_pub]);
        let mac1 = mac(&mac1_key, &out[..60]);
        out[60..76].copy_from_slice(&mac1);

        // Padding `S2` перед ответом, ответ целиком под защитой, затем хвост.
        let mut response = TestObf::padding(self.obf.s2);
        response.extend_from_slice(&out);
        self.obf.protect(
            &mut response,
            self.obf.s2,
            self.obf.s2 + RESPONSE_MESSAGE_LEN,
        );
        response.extend_from_slice(&TestObf::padding(self.obf.response_trailer));
        self.socket.send(&response).await.expect("ответ отправлен");

        // У ответчика порядок ключей обратный (`BeginSymmetricSession`).
        let (recv_key, send_key) = kdf2(&chaining_key, &[]);
        let session = ServerSession {
            recv_key,
            send_key,
            local_index: server_local_index,
            remote_index: init.sender_index,
        };
        (session, prelude)
    }

    /// Рукопожатие и эхо пакетов, пока сокет не откажет.
    async fn run_one_handshake_then_echo(self) {
        self.run_echo(|_, _| {}).await;
    }

    /// Рукопожатие и эхо; `observe` видит prelude и каждый расшифрованный текст
    /// (с добавкой нулей, если клиент её дописал). Эхо возвращает текст как есть.
    async fn run_echo(self, mut observe: impl FnMut(&[Vec<u8>], &[u8])) {
        let (session, prelude) = self.perform_handshake().await;
        let mut buf = [0u8; 2048];
        let mut tx_counter: u64 = 0;

        loop {
            let Ok(len) = self.socket.recv(&mut buf).await else {
                return;
            };
            let Some(frame) = self.deobfuscate_transport(&buf[..len]) else {
                continue;
            };
            let Some(plaintext) = session.decrypt(&frame) else {
                continue;
            };
            if plaintext.iter().all(|&b| b == 0) {
                // Keepalive (возможно, с добавкой): отвечать нечем.
                continue;
            }
            observe(&prelude, &plaintext);

            let reply = self.obfuscate_transport(session.seal(&plaintext, &mut tx_counter));
            if self.socket.send(&reply).await.is_err() {
                return;
            }
        }
    }

    /// Рукопожатие и ожидание первого keepalive.
    async fn run_handshake_then_wait_for_keepalive(self) {
        let (session, _) = self.perform_handshake().await;
        let mut buf = [0u8; 2048];
        loop {
            let Ok(len) = self.socket.recv(&mut buf).await else {
                return;
            };
            if let Some(frame) = self.deobfuscate_transport(&buf[..len])
                && let Some(plaintext) = session.decrypt(&frame)
                && plaintext.is_empty()
            {
                return;
            }
        }
    }
}

/// Ключи и индексы сеанса со стороны поддельного сервера.
struct ServerSession {
    recv_key: [u8; KEY_LEN],
    send_key: [u8; KEY_LEN],
    local_index: u32,
    remote_index: u32,
}

impl ServerSession {
    /// Проверяет и расшифровывает один входящий пакет данных.
    fn decrypt(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        if datagram.first().copied() != Some(MESSAGE_TRANSPORT_DATA) {
            return None;
        }
        let (header, ciphertext) = transport::split(datagram).ok()?;
        if header.receiver_index != self.local_index {
            return None;
        }
        aead_open(&self.recv_key, header.counter, ciphertext, &[]).ok()
    }

    /// Шифрует ответ своим ключом отправки, продвигая счётчик.
    fn seal(&self, plaintext: &[u8], tx_counter: &mut u64) -> Vec<u8> {
        let sealed = aead_seal(&self.send_key, *tx_counter, plaintext, &[]);
        let header = transport::TransportHeader {
            receiver_index: self.remote_index,
            counter: *tx_counter,
        };
        *tx_counter += 1;
        transport::build(&header, [0, 0, 0], &sealed)
    }
}

fn client_config(server: &FakeServer, client_private: &StaticSecret) -> WireguardConfig {
    WireguardConfig {
        server: SocketAddress::ip(server.address().ip(), server.address().port()),
        private_key: penguin_core::base64::encode(&client_private.to_bytes()),
        server_public_key: server.public_base64(),
        address_ipv4: "10.0.0.2/32".to_owned(),
        keepalive_secs: 0,
        ..WireguardConfig::default()
    }
}

#[tokio::test]
async fn a_client_completes_the_handshake_and_exchanges_data_with_a_real_socket() {
    let server = FakeServer::start().await;
    let client_private = StaticSecret::random();
    let config = client_config(&server, &client_private);
    tokio::spawn(server.run_one_handshake_then_echo());

    let outbound = tokio::time::timeout(
        PATIENCE,
        WireguardOutbound::connect(OutboundId::from("тест"), config, Arc::new(LocalDialer)),
    )
    .await
    .expect("рукопожатие уложилось в срок")
    .expect("рукопожатие прошло");

    assert_eq!(outbound.interface().mtu, 1420);

    let packet = ip_packet(b"hello, tunnel");
    outbound.send(&packet).await.expect("пакет отправлен");

    let echoed = tokio::time::timeout(PATIENCE, outbound.recv())
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(&echoed[..], &packet[..]);

    outbound.close().await.expect("закрывается");
}

#[tokio::test]
async fn a_silent_client_still_sends_a_keepalive_before_nat_forgets_it() {
    // Таймер драйвера: keepalive в одну секунду, чтобы дождаться его в тесте.
    let server = FakeServer::start().await;
    let client_private = StaticSecret::random();
    let config = WireguardConfig {
        keepalive_secs: 1,
        ..client_config(&server, &client_private)
    };
    let server_task = tokio::spawn(server.run_handshake_then_wait_for_keepalive());

    let outbound = tokio::time::timeout(
        PATIENCE,
        WireguardOutbound::connect(OutboundId::from("тест"), config, Arc::new(LocalDialer)),
    )
    .await
    .expect("рукопожатие уложилось в срок")
    .expect("рукопожатие прошло");

    // Клиент сам ничего не шлёт: весь трафик - keepalive таймера.
    tokio::time::timeout(PATIENCE, server_task)
        .await
        .expect("keepalive не пришёл вовремя")
        .expect("задача сервера не запаниковала");

    outbound.close().await.expect("закрывается");
}

#[tokio::test]
async fn after_close_the_background_task_stops_and_send_reports_it() {
    let server = FakeServer::start().await;
    let client_private = StaticSecret::random();
    let config = client_config(&server, &client_private);
    tokio::spawn(server.run_one_handshake_then_echo());

    let outbound = tokio::time::timeout(
        PATIENCE,
        WireguardOutbound::connect(OutboundId::from("тест"), config, Arc::new(LocalDialer)),
    )
    .await
    .expect("рукопожатие уложилось в срок")
    .expect("рукопожатие прошло");

    outbound.close().await.expect("закрывается");

    let err = outbound
        .send("после закрытия".as_bytes())
        .await
        .expect_err("закрытое направление обязано отказать");
    assert!(err.to_string().contains("закрыт"), "{err}");
}

#[tokio::test]
async fn a_handshake_with_no_server_on_the_other_end_times_out_instead_of_hanging() {
    // Порт занят, но никто не отвечает.
    let dead_socket = UdpSocket::bind("127.0.0.1:0").await.expect("слушается");
    let dead_addr = dead_socket.local_addr().expect("адрес");
    drop(dead_socket);

    let client_private = StaticSecret::random();
    let config = WireguardConfig {
        server: SocketAddress::ip(dead_addr.ip(), dead_addr.port()),
        private_key: penguin_core::base64::encode(&client_private.to_bytes()),
        server_public_key: penguin_core::base64::encode(
            PublicKey::from(&StaticSecret::random()).as_bytes(),
        ),
        address_ipv4: "10.0.0.2/32".to_owned(),
        ..WireguardConfig::default()
    };

    // Внешний срок короче `REKEY_ATTEMPT_TIME`; важно лишь, что подключения нет.
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        WireguardOutbound::connect(OutboundId::from("тест"), config, Arc::new(LocalDialer)),
    )
    .await;
    match outcome {
        Err(_elapsed) => {}
        Ok(Err(_wireguard_error)) => {}
        Ok(Ok(_outbound)) => panic!("подключение не должно было состояться: сервера нет"),
    }
}

#[tokio::test]
async fn an_amneziawg_client_handshakes_and_echoes_through_junk_padding_and_magic_headers() {
    // Параметры в духе выданной Amnezia: junk-пакеты, padding инициации и ответа,
    // магические заголовки H1/H2/H4. Сервер говорит на тех же параметрах.
    let obf = TestObf {
        s1: 15,
        s2: 17,
        s4: 0,
        h1: 0x4C56_8A11,
        h2: 0x7D21_93FE,
        h4: 0x5E6F_7A8B,
        ..TestObf::NONE
    };
    let server = FakeServer::start_with_obf(obf).await;
    let client_private = StaticSecret::random();
    let address = server.address();

    let config: WireguardConfig = serde_json::from_value(serde_json::json!({
        "server": format!("{}:{}", address.ip(), address.port()),
        "private_key": penguin_core::base64::encode(&client_private.to_bytes()),
        "server_public_key": server.public_base64(),
        "address_ipv4": "10.0.0.2/32",
        "keepalive_secs": 0,
        "amnezia": {
            "jc": 2,
            "jmin": 40,
            "jmax": 70,
            "s1": 15,
            "s2": 17,
            "h1": 0x4C56_8A11u32,
            "h2": 0x7D21_93FEu32,
            "h3": 3,
            "h4": 0x5E6F_7A8Bu32,
        },
    }))
    .expect("настройки AmneziaWG разбираются");

    tokio::spawn(server.run_one_handshake_then_echo());

    let outbound = tokio::time::timeout(
        PATIENCE,
        WireguardOutbound::connect(OutboundId::from("awg"), config, Arc::new(LocalDialer)),
    )
    .await
    .expect("рукопожатие уложилось в срок")
    .expect("рукопожатие AmneziaWG прошло");

    let packet = ip_packet(b"amnezia tunnel");
    outbound.send(&packet).await.expect("пакет отправлен");

    let echoed = tokio::time::timeout(PATIENCE, outbound.recv())
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(&echoed[..], &packet[..]);

    outbound.close().await.expect("закрывается");
}

#[tokio::test]
async fn an_amneziawg_3_client_talks_through_header_protection_signatures_and_padding() {
    // Набор премиум-сервера Amnezia: защита заголовков, `I1`/`I2`, добавка к
    // содержимому, хвосты. Сервер снимает защиту своим кодом по эталону.
    let key = [0x5Cu8; 32];
    let obf = TestObf {
        s1: 15,
        s2: 18,
        s4: 23,
        h1: 0x4C56_8A11,
        h2: 0x7D21_93FE,
        h4: 0x5E6F_7A8B,
        key: Some(key),
        response_trailer: 37,
    };
    let server = FakeServer::start_with_obf(obf).await;
    let client_private = StaticSecret::random();
    let address = server.address();

    let config: WireguardConfig = serde_json::from_value(serde_json::json!({
        "server": format!("{}:{}", address.ip(), address.port()),
        "private_key": penguin_core::base64::encode(&client_private.to_bytes()),
        "server_public_key": server.public_base64(),
        "address_ipv4": "10.0.0.2/32",
        "keepalive_secs": 0,
        "amnezia": {
            "jc": 2, "jmin": 40, "jmax": 70,
            "s1": 15, "s2": 18, "s3": 12, "s4": 23,
            "h1": 0x4C56_8A11u32, "h2": 0x7D21_93FEu32, "h3": 3, "h4": 0x5E6F_7A8Bu32,
            "i1": "<b 0xc0ffee><r 4>",
            "i2": "<rd 5>",
            "header_protection_key": penguin_core::base64::encode(&key),
            "content_padding_addition": "9",
            "random_trailers": true,
        },
    }))
    .expect("настройки AmneziaWG 3 разбираются");

    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(server.run_echo(move |prelude, plaintext| {
        let _ = seen_tx.send((prelude.to_vec(), plaintext.to_vec()));
    }));

    let outbound = tokio::time::timeout(
        PATIENCE,
        WireguardOutbound::connect(OutboundId::from("awg3"), config, Arc::new(LocalDialer)),
    )
    .await
    .expect("рукопожатие уложилось в срок")
    .expect("рукопожатие AmneziaWG 3 прошло");

    let packet = ip_packet(b"amnezia 3 tunnel");
    outbound.send(&packet).await.expect("пакет отправлен");

    let (prelude, plaintext) = tokio::time::timeout(PATIENCE, seen_rx.recv())
        .await
        .expect("сервер не увидел пакет")
        .expect("наблюдение пришло");
    // Сигнатуры первыми и по порядку, затем два junk.
    assert_eq!(prelude.len(), 2 + 2, "{prelude:?}");
    assert_eq!(&prelude[0][..3], &[0xc0, 0xff, 0xee]);
    assert_eq!(prelude[0].len(), 3 + 4);
    assert!(prelude[1].len() == 5 && prelude[1].iter().all(u8::is_ascii_digit));
    // Добавка `content_padding_addition` — нули под шифром после IP-пакета.
    assert_eq!(&plaintext[..packet.len()], &packet[..]);
    assert_eq!(&plaintext[packet.len()..], &[0u8; 9]);

    // Эхо приходит с той же добавкой; клиент режет её по длине из IP-заголовка.
    let echoed = tokio::time::timeout(PATIENCE, outbound.recv())
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(&echoed[..], &packet[..]);

    outbound.close().await.expect("закрывается");
}
