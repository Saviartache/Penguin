//! Направление против поддельного сервера — через настоящий сокет UDP.
//!
//! Юнит-тесты `crypto::handshake` проверяют формулы рукопожатия
//! независимо от сети. Этот файл проверяет то, чего по отдельным файлам не
//! видно: что `WireguardOutbound::connect` доводит рукопожатие до конца по
//! настоящему сокету, что `send`/`recv` шифруют и расшифровывают пакеты
//! данных так, что сервер (свой, поддельный) их принимает и понимает, и что
//! `close()` действительно останавливает фоновую задачу, а не просто
//! возвращает `Ok`.
//!
//! Сервер здесь — реализация роли ответчика по тем же формулам спецификации,
//! написанная заново по общим примитивам крейта (`crypto::primitives`,
//! `frame::*`), а не скопированная из юнит-теста `crypto::handshake`: крейт
//! роль ответчика не реализует и не экспортирует, а тест на настоящем сокете
//! обязан играть обе стороны сам.

// Проверка падает там, где сервер или клиент повели себя не по протоколу —
// это провалившийся тест, а не путь соединения в проде.
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
    CONSTRUCTION, IDENTIFIER, KEY_LEN, LABEL_MAC1, MESSAGE_RESPONSE, MESSAGE_TRANSPORT_DATA,
    RESPONSE_MESSAGE_LEN,
};
use penguin_wireguard::crypto::primitives::{aead_open, aead_seal, hash, kdf2, kdf3, mac};
use penguin_wireguard::frame::{initiation, transport};
use penguin_wireguard::outbound::WireguardOutbound;
use tokio::net::{TcpStream, UdpSocket};
use x25519_dalek::{PublicKey, StaticSecret};

/// Сколько ждать событие, прежде чем считать, что его не будет.
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

/// Поддельный сервер: играет роль ответчика Noise IK по тем же формулам,
/// что настоящий, и после рукопожатия эхом отвечает на пакеты данных.
struct FakeServer {
    socket: UdpSocket,
    private: StaticSecret,
    public: PublicKey,
}

impl FakeServer {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("слушается");
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);
        Self {
            socket,
            private,
            public,
        }
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().expect("адрес")
    }

    fn public_base64(&self) -> String {
        penguin_core::base64::encode(self.public.as_bytes())
    }

    /// Проводит одно рукопожатие (мы — ответчик) и возвращает ключи и
    /// индексы установленного сеанса вместе с уже прочитанным буфером на
    /// случай, если следом сразу пришёл пакет данных.
    async fn perform_handshake(&self) -> ServerSession {
        let mut buf = [0u8; 2048];
        let (len, client_addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .expect("инициация пришла");
        self.socket
            .connect(client_addr)
            .await
            .expect("подключение к клиенту");

        let init = initiation::parse(&buf[..len]).expect("инициация разбирается");

        // Шаги 1-2 (сторона ответчика): те же формулы, что у инициатора, но
        // хэш замешивает СВОЙ статический ключ (это ответчик), а не чужой.
        let mut chaining_key = hash(&[CONSTRUCTION]);
        let mut transcript = hash(&[&chaining_key, IDENTIFIER]);
        transcript = hash(&[&transcript, self.public.as_bytes()]);

        // Шаг 3 (со стороны ответчика: смешать эфемерный ключ ИНИЦИАТОРА).
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

        // Шаг 6: та же общая точка Диффи-Хеллмана статика-статика.
        let ss_static = *self
            .private
            .diffie_hellman(&PublicKey::from(initiator_static_pub))
            .as_bytes();
        let (ck, key) = kdf2(&chaining_key, &ss_static);
        chaining_key = ck;
        let _timestamp = aead_open(&key, 0, &init.timestamp_ciphertext, &transcript)
            .expect("метка времени расшифровывается");
        transcript = hash(&[&transcript, &init.timestamp_ciphertext]);

        // Сообщение 2: свой эфемерный ключ, тройное смешивание, PSK (пустой).
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
        out[0] = MESSAGE_RESPONSE;
        out[4..8].copy_from_slice(&server_local_index.to_le_bytes());
        out[8..12].copy_from_slice(&init.sender_index.to_le_bytes());
        out[12..44].copy_from_slice(&ephemeral_public);
        out[44..60].copy_from_slice(&empty_ciphertext);
        let mac1_key = hash(&[LABEL_MAC1, &initiator_static_pub]);
        let mac1 = mac(&mac1_key, &out[..60]);
        out[60..76].copy_from_slice(&mac1);

        self.socket.send(&out).await.expect("ответ отправлен");

        // Ключи сеанса со стороны ответчика: порядок обратный инициатору
        // (см. `BeginSymmetricSession` в `device/noise-protocol.go`).
        let (recv_key, send_key) = kdf2(&chaining_key, &[]);
        ServerSession {
            recv_key,
            send_key,
            local_index: server_local_index,
            remote_index: init.sender_index,
        }
    }

    /// Проводит рукопожатие и дальше эхом отвечает на пакеты данных, пока
    /// сокет не откажет.
    async fn run_one_handshake_then_echo(self) {
        let session = self.perform_handshake().await;
        let mut buf = [0u8; 2048];
        let mut tx_counter: u64 = 0;

        loop {
            let Ok(len) = self.socket.recv(&mut buf).await else {
                return;
            };
            let Some(plaintext) = session.decrypt(&buf[..len]) else {
                continue;
            };
            if plaintext.is_empty() {
                // Keepalive от клиента — эху отвечать нечем, а сама метка
                // подлинности уже подтвердила, что сеанс с обеих сторон жив.
                continue;
            }

            let reply = session.seal(&plaintext, &mut tx_counter);
            if self.socket.send(&reply).await.is_err() {
                return;
            }
        }
    }

    /// Проводит рукопожатие и ждёт первый пакет данных с пустым открытым
    /// текстом — то есть keepalive, который клиент никто не просил слать.
    async fn run_handshake_then_wait_for_keepalive(self) {
        let session = self.perform_handshake().await;
        let mut buf = [0u8; 2048];
        loop {
            let Ok(len) = self.socket.recv(&mut buf).await else {
                return;
            };
            if let Some(plaintext) = session.decrypt(&buf[..len])
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

    outbound
        .send(b"hello, tunnel")
        .await
        .expect("пакет отправлен");

    let echoed = tokio::time::timeout(PATIENCE, outbound.recv())
        .await
        .expect("ответ не пришёл")
        .expect("читается");
    assert_eq!(&echoed[..], b"hello, tunnel");

    outbound.close().await.expect("закрывается");
}

#[tokio::test]
async fn a_silent_client_still_sends_a_keepalive_before_nat_forgets_it() {
    // Настройки-таймер (`crate::outbound::driver`) — ветка кода, которую
    // остальные тесты этого файла не задевают вовсе: там либо шлют данные
    // сами, либо не ждут достаточно долго. Здесь keepalive выставлен в одну
    // секунду именно затем, чтобы дождаться его в разумное время теста, а не
    // затем, что так будет в настоящих настройках (`DEFAULT_KEEPALIVE_SECS`
    // — 25, см. `crate::crypto::constants`).
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

    // Клиент ничего не посылает сам — весь трафик ниже должен быть
    // keepalive, который завёл именно таймер направления.
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

    // Фоновая задача забрала с собой получающий конец канала — послать
    // пакет в закрытое направление больше нельзя.
    let err = outbound
        .send("после закрытия".as_bytes())
        .await
        .expect_err("закрытое направление обязано отказать");
    assert!(err.to_string().contains("закрыт"), "{err}");
}

#[tokio::test]
async fn a_handshake_with_no_server_on_the_other_end_times_out_instead_of_hanging() {
    // Никакого `FakeServer` не поднимаем: порт занят, но никто не отвечает.
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

    // `REKEY_ATTEMPT_TIME` — девяносто секунд; тест не ждёт их: снаружи ещё
    // один срок покороче. Не важно, что именно случится раньше — внешний
    // срок или отказ ОС (закрытый порт на loopback нередко возвращает ICMP
    // «недоступно», и это тоже не должно выглядеть зависанием), — важно,
    // чтобы подключение не состоялось: сервера на том конце нет.
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
