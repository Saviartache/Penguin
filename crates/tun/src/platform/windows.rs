//! Wintun: загрузка драйвера, адаптер, сессия чтения-записи.
//!
//! Чтение блокирующее, поэтому идёт в отдельном потоке (не `spawn_blocking`:
//! читает непрерывно) и отдаёт пакеты задаче через очередь.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::sync::{Mutex, mpsc};

use crate::config::TunConfig;
use crate::device::TunDevice;
use crate::error::{TunError, TunResult};

/// Глубина очереди; при переполнении пакеты отбрасываются.
const QUEUE_CAPACITY: usize = 1024;

/// Пакетов на одну аллокацию буфера чтения.
const BATCH: usize = 16;

/// Размер буфера на один пакет.
const SLOT: usize = 2048;

/// Тип тоннеля, под которым адаптер виден в системе.
const TUNNEL_TYPE: &str = "Penguin";

/// Имя файла драйвера.
const DRIVER: &str = "wintun.dll";

/// Загружает драйвер из каталога исполняемого файла; нет каталога — обычный поиск.
pub fn load_driver() -> TunResult<wintun::Wintun> {
    let directory = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf));

    #[allow(unsafe_code, reason = "загрузка wintun.dll")]
    // SAFETY: загружается подписанная библиотека драйвера, один раз.
    let loaded = match &directory {
        Some(directory) => unsafe { wintun::load_from_path(directory.join(DRIVER)) },
        None => unsafe { wintun::load() },
    };

    loaded.map_err(|err| {
        tracing::debug!(%err, ?directory, "не удалось загрузить {DRIVER}");
        TunError::driver_missing(
            directory
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("каталог программы")),
        )
    })
}

/// Адаптер Wintun.
pub struct WintunDevice {
    session: Arc<wintun::Session>,
    adapter: Arc<wintun::Adapter>,
    incoming: Mutex<mpsc::Receiver<BytesMut>>,
    name: String,
    mtu: u16,
    index: Option<u32>,
}

impl std::fmt::Debug for WintunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WintunDevice")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("index", &self.index)
            .finish()
    }
}

impl WintunDevice {
    /// Создаёт адаптер и начинает чтение.
    pub async fn open(config: &TunConfig) -> TunResult<Self> {
        let wintun = load_driver()?;

        let adapter = wintun::Adapter::create(&wintun, &config.name, TUNNEL_TYPE, None)
            .map_err(|err| classify(&config.name, err))?;

        adapter
            .set_network_addresses_tuple(
                config.address(),
                std::net::IpAddr::V4(config.ipv4_netmask()),
                None,
            )
            .map_err(|err| TunError::adapter(&config.name, err))?;

        let index = adapter.get_adapter_index().ok();
        let session = adapter
            .start_session(config.ring_capacity)
            .map_err(|err| TunError::adapter(&config.name, err))?;
        let session = Arc::new(session);

        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        spawn_reader(Arc::clone(&session), tx);

        tracing::info!(
            name = config.name,
            mtu = config.mtu,
            index = index.unwrap_or(0),
            "адаптер поднят"
        );

        Ok(Self {
            session,
            adapter,
            incoming: Mutex::new(rx),
            name: config.name.clone(),
            mtu: config.mtu,
            index,
        })
    }

    /// Адаптер, если он понадобился платформенному коду.
    pub fn adapter(&self) -> &Arc<wintun::Adapter> {
        &self.adapter
    }
}

/// Запускает поток чтения из кольца драйвера.
fn spawn_reader(session: Arc<wintun::Session>, tx: mpsc::Sender<BytesMut>) {
    let spawned = std::thread::Builder::new()
        .name("penguin-tun-read".to_owned())
        .spawn(move || read_loop(&session, &tx));
    if let Err(err) = spawned {
        tracing::error!(%err, "не удалось запустить чтение из адаптера");
    }
}

/// Читает кольцо, пока сессия жива; `try_send`, чтобы не копить пакеты в кольце драйвера.
fn read_loop(session: &Arc<wintun::Session>, tx: &mpsc::Sender<BytesMut>) {
    let mut buffer = BytesMut::new();
    loop {
        let packet = match session.receive_blocking() {
            Ok(packet) => packet,
            Err(err) => {
                tracing::debug!(%err, "чтение из адаптера прекращено");
                return;
            }
        };
        let bytes = packet.bytes();
        if buffer.capacity() < bytes.len() {
            buffer.reserve(BATCH * SLOT.max(bytes.len()));
        }
        buffer.extend_from_slice(bytes);
        match tx.try_send(buffer.split()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::trace!("очередь пакетов переполнена, пакет отброшен");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return,
        }
    }
}

/// Переводит ошибку создания адаптера в понятную пользователю.
fn classify(name: &str, err: wintun::Error) -> TunError {
    let text = err.to_string();
    // Библиотека отдаёт код Windows строкой.
    if text.contains("Access is denied") || text.contains("отказано в доступе") {
        return TunError::PermissionDenied;
    }
    TunError::adapter(name, text)
}

#[async_trait]
impl TunDevice for WintunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn index(&self) -> Option<u32> {
        self.index
    }

    async fn recv(&self) -> TunResult<BytesMut> {
        let mut incoming = self.incoming.lock().await;
        incoming.recv().await.ok_or(TunError::Closed)
    }

    fn try_recv(&self) -> Option<BytesMut> {
        self.incoming.try_lock().ok()?.try_recv().ok()
    }

    async fn send(&self, packet: &[u8]) -> TunResult<()> {
        if packet.len() > self.mtu as usize {
            return Err(TunError::PacketTooLarge {
                size: packet.len(),
                mtu: self.mtu,
            });
        }

        let mut allocated = self
            .session
            .allocate_send_packet(packet.len() as u16)
            .map_err(|err| TunError::adapter(&self.name, err))?;
        allocated.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(allocated);
        Ok(())
    }

    async fn close(&self) -> TunResult<()> {
        // Читающий поток выйдет сам: `receive_blocking` вернёт ошибку.
        self.session
            .shutdown()
            .map_err(|err| TunError::adapter(&self.name, err))?;
        tracing::info!(name = self.name, "адаптер опущен");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_is_bounded() {
        const { assert!(QUEUE_CAPACITY > 0 && QUEUE_CAPACITY <= 8192) };
    }

    #[test]
    fn access_denied_becomes_a_permission_error() {
        let err = classify(
            "Penguin",
            wintun::Error::from("Access is denied. (os error 5)"),
        );
        assert!(matches!(err, TunError::PermissionDenied));
        assert!(err.needs_user_action());
    }

    #[test]
    fn other_failures_keep_the_adapter_name() {
        let err = classify("Penguin", wintun::Error::from("что-то пошло не так"));
        assert!(err.to_string().contains("Penguin"));
    }

    #[tokio::test]
    async fn opening_without_privileges_fails_clearly() {
        let config = TunConfig {
            name: "PenguinTest".to_owned(),
            ..TunConfig::default()
        };
        match WintunDevice::open(&config).await {
            Ok(device) => {
                assert_eq!(device.name(), "PenguinTest");
                device.close().await.expect("закрывается");
            }
            Err(err) => {
                assert!(
                    err.needs_user_action() || matches!(err, TunError::AdapterCreation { .. }),
                    "неожиданная ошибка: {err}"
                );
            }
        }
    }
}
