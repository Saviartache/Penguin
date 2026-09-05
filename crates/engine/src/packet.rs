//! Направление уровня пакетов как устройство для стека.
//!
//! Тот самый шов, ради которого `PacketOutbound` и объявлен так, как объявлен.
//! У него `mtu`, `send`, `recv` — ровно то же, что у [`penguin_tun::TunDevice`].
//! Значит направление подставляется исходящему стеку **как устройство**, и
//! `netstack` про WireGuard, OpenConnect и `CONNECT-IP` по-прежнему не знает
//! ничего.
//!
//! ```text
//!  приложение ──► TUN ──► netstack::stack ──► router ──┬─► Outbound ──────────► сервер
//!                          (принимает)                 │
//!                                                      └─► PacketOutbound
//!                                                            │ здесь переходник
//!                                                            ▼
//!                                            netstack::outgoing (открывает)
//! ```
//!
//! # Почему переходник здесь, а не в стеке или в протоколе
//!
//! В стеке нельзя: `netstack` не зависит от `penguin-proto` и не должен —
//! иначе он узнает про протоколы. В протоколе нельзя: крейт протокола не
//! зависит от `penguin-tun` (`AGENTS.md` §1.1), да и `smoltcp` ему не нужен.
//! В движке можно: он и так держит оба.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use penguin_netstack::config::StackConfig;
use penguin_proto::packet::PacketOutbound;
use penguin_tun::TunDevice;
use penguin_tun::error::{TunError, TunResult};

/// Направление уровня пакетов, надетое на трейт устройства.
pub struct PacketDevice {
    outbound: Arc<dyn PacketOutbound>,
    name: String,
    mtu: u16,
}

impl PacketDevice {
    /// Надевает переходник.
    ///
    /// Имя и MTU спрашиваются один раз и запоминаются: интерфейс внутри
    /// тоннеля не меняется, пока направление живо, а `name` обязан вернуть
    /// ссылку.
    pub fn new(outbound: Arc<dyn PacketOutbound>) -> Self {
        let interface = outbound.interface();
        Self {
            name: outbound.protocol().to_owned(),
            mtu: interface.mtu,
            outbound,
        }
    }

    /// Настройки стека по интерфейсу, который выдал сервер.
    ///
    /// Адреса берутся у направления, а не из настроек профиля: у WireGuard они
    /// в конфигурации, а у OpenConnect приходят при входе вместе с маршрутами.
    pub fn stack_config(&self) -> StackConfig {
        let interface = self.outbound.interface();
        StackConfig {
            ipv4: interface.ipv4,
            ipv6: interface.ipv6,
            mtu: interface.mtu,
            ..StackConfig::default()
        }
    }
}

impl std::fmt::Debug for PacketDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketDevice")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish()
    }
}

#[async_trait]
impl TunDevice for PacketDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Индекса у виртуального интерфейса нет: маршруты на него не ставят —
    /// он живёт внутри клиента, а не в системе.
    fn index(&self) -> Option<u32> {
        None
    }

    async fn recv(&self) -> TunResult<BytesMut> {
        match self.outbound.recv().await {
            Ok(packet) => Ok(BytesMut::from(&packet[..])),
            // Стек различает только «закрыто» и «ошибка чтения», а причина
            // отказа направления нужна выше — там, где решают, повторять ли.
            // Здесь она уже записана в журнал самим направлением.
            Err(err) => {
                tracing::debug!(%err, "направление больше не отдаёт пакеты");
                Err(TunError::Closed)
            }
        }
    }

    async fn send(&self, packet: &[u8]) -> TunResult<()> {
        self.outbound
            .send(packet)
            .await
            .map_err(|err| TunError::Io(std::io::Error::other(err.to_string())))
    }

    async fn close(&self) -> TunResult<()> {
        let _ = self.outbound.close().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use bytes::Bytes;
    use penguin_core::id::OutboundId;
    use penguin_proto::error::ProtocolError;
    use penguin_proto::packet::PacketInterface;

    use super::*;

    /// Направление, которое отдаёт заранее сложенные пакеты.
    struct Fake {
        interface: PacketInterface,
        incoming: Mutex<Vec<Bytes>>,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl Fake {
        fn new(incoming: Vec<Bytes>) -> Arc<Self> {
            Arc::new(Self {
                interface: PacketInterface {
                    ipv4: (Ipv4Addr::new(10, 7, 0, 2), 24),
                    ipv6: None,
                    mtu: 1420,
                },
                incoming: Mutex::new(incoming),
                sent: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl PacketOutbound for Fake {
        fn id(&self) -> OutboundId {
            OutboundId::new("проверка")
        }

        fn protocol(&self) -> &'static str {
            "wireguard"
        }

        fn interface(&self) -> PacketInterface {
            self.interface.clone()
        }

        async fn send(&self, packet: &[u8]) -> Result<(), ProtocolError> {
            self.sent.lock().expect("замок").push(packet.to_vec());
            Ok(())
        }

        async fn recv(&self) -> Result<Bytes, ProtocolError> {
            let next = self.incoming.lock().expect("замок").pop();
            match next {
                Some(packet) => Ok(packet),
                // Пакеты кончились: ведём себя как закрывшееся направление.
                None => Err(ProtocolError::Disconnected("пакеты кончились".to_owned())),
            }
        }
    }

    #[tokio::test]
    async fn the_interface_the_server_gave_becomes_the_stack_settings() {
        // Адреса приходят от сервера, а не из настроек профиля: у OpenConnect
        // они выдаются при входе вместе с маршрутами.
        let device = PacketDevice::new(Fake::new(Vec::new()));
        let config = device.stack_config();

        assert_eq!(config.ipv4, (Ipv4Addr::new(10, 7, 0, 2), 24));
        assert_eq!(config.mtu, 1420);
        assert_eq!(device.mtu(), 1420);
        assert_eq!(device.name(), "wireguard");
    }

    #[tokio::test]
    async fn packets_pass_through_unchanged_in_both_directions() {
        let outbound = Fake::new(vec![Bytes::from_static(b"from the tunnel")]);
        let device = PacketDevice::new(Arc::clone(&outbound) as Arc<dyn PacketOutbound>);

        let got = device.recv().await.expect("пакет есть");
        assert_eq!(&got[..], b"from the tunnel");

        device.send(b"to the tunnel").await.expect("ушёл");
        assert_eq!(
            outbound.sent.lock().expect("замок").as_slice(),
            [b"to the tunnel".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_direction_that_stopped_reads_as_a_closed_adapter() {
        // Иначе цикл стека принял бы это за случайный сбой чтения и продолжил
        // крутиться на мёртвом направлении.
        let device = PacketDevice::new(Fake::new(Vec::new()));
        assert!(matches!(device.recv().await.unwrap_err(), TunError::Closed));
    }

    #[tokio::test]
    async fn the_mtu_is_the_one_from_inside_the_tunnel() {
        // У WireGuard это 1420 при внешних 1500: соврать здесь — значит
        // объявить приложению MSS, который не проходит.
        let device = PacketDevice::new(Fake::new(Vec::new()));
        assert!(
            device.mtu() < 1500,
            "MTU тоннеля не может равняться внешнему"
        );
    }
}
