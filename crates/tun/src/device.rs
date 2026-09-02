//! `TunDevice` — трейт устройства. Выше по стеку платформы не видно.
//!
//! Устройство отдаёт и принимает **IP-пакеты целиком**: ни канального
//! заголовка, ни границ кадров здесь нет. Что с ними делать, знает
//! `penguin-netstack`.

use async_trait::async_trait;
use bytes::BytesMut;

use crate::config::TunConfig;
use crate::error::TunResult;

/// Виртуальный сетевой интерфейс.
#[async_trait]
pub trait TunDevice: Send + Sync + 'static {
    /// Имя адаптера в системе.
    fn name(&self) -> &str;

    /// Наибольший размер пакета.
    fn mtu(&self) -> u16;

    /// Индекс интерфейса — по нему платформа ставит маршруты.
    fn index(&self) -> Option<u32> {
        None
    }

    /// Ждёт следующий пакет от системы.
    ///
    /// Пакет приходит владением, а не в предоставленный буфер: у Wintun он и
    /// так лежит в кольце драйвера, и лишняя копия в чужой буфер ничего не
    /// экономит.
    async fn recv(&self) -> TunResult<BytesMut>;

    /// Забирает уже пришедший пакет, не дожидаясь нового.
    ///
    /// Нужно стеку для чтения пачкой: за время разбора одного пакета обычно
    /// приходит ещё несколько, и опрашивать стек на каждый — расточительно.
    /// `None` означает «пока пусто», а не ошибку.
    ///
    /// Умолчание — всегда `None`: реализация без очереди ничего не теряет,
    /// просто читает по одному.
    fn try_recv(&self) -> Option<BytesMut> {
        None
    }

    /// Отправляет пакет системе.
    async fn send(&self, packet: &[u8]) -> TunResult<()>;

    /// Закрывает адаптер.
    ///
    /// После этого [`Self::recv`] возвращает [`crate::error::TunError::Closed`],
    /// и читающая задача завершается сама.
    async fn close(&self) -> TunResult<()>;
}

/// Открывает устройство для текущей платформы.
pub async fn open(config: &TunConfig) -> TunResult<Box<dyn TunDevice>> {
    #[cfg(windows)]
    {
        Ok(Box::new(
            crate::platform::windows::WintunDevice::open(config).await?,
        ))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(
            crate::platform::linux::LinuxTun::open(config).await?,
        ))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = config;
        Err(crate::error::TunError::Unsupported)
    }
}

/// Есть ли драйвер, без которого тоннель не поднимется.
///
/// Отдельно от [`open`] и **до** попытки подключиться: на Windows `wintun.dll`
/// в поставку системы не входит, и её отсутствие — самая частая причина
/// «тоннель не включается». Узнать об этом из проверки окружения лучше, чем из
/// ошибки посреди подключения.
///
/// `Ok(())` не обещает, что адаптер создастся: на это нужны ещё и права.
pub fn driver_available() -> TunResult<()> {
    #[cfg(windows)]
    {
        // Библиотека только загружается: адаптер не создаётся, права не
        // нужны, следов в системе не остаётся.
        crate::platform::windows::load_driver().map(|_| ())
    }
    #[cfg(target_os = "linux")]
    {
        // `/dev/net/tun` создаётся модулем ядра; без него открывать нечего.
        if std::path::Path::new("/dev/net/tun").exists() {
            Ok(())
        } else {
            Err(crate::error::TunError::TunModuleMissing)
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err(crate::error::TunError::Unsupported)
    }
}
