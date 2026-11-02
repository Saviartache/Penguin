//! I2P: выход в интернет через outproxy сети I2P. Медленно, зато трафик похож на I2P, а не на VPN.
//!
//! Сам I2P-маршрутизатор — отдельная программа (i2pd), её запускает движок; протокол
//! говорит только с её HTTP-прокси на `127.0.0.1`. Два `CONNECT` подряд:
//!
//! ```text
//!  CONNECT <outproxy>.b32.i2p:80   i2pd открывает поток I2P до outproxy и отдаёт его как есть
//!  CONNECT example.com:443         это уже outproxy: он выходит в интернет
//! ```
//!
//! Так outproxy задаётся профилем, а не настройками i2pd.
//!
//! - UDP нет: outproxy возит только TCP.
//! - Имя назначения уходит доменом, разрешает его outproxy.
//! - Пароля нет, и `AuthRejected` не бывает: outproxy пускает всех.
//! - Весь трафик видит оператор outproxy; окно говорит об этом в форме.

pub mod config;
pub mod error;
pub mod factory;
pub mod handshake;
pub mod outbound;
pub mod response;

pub use config::I2pConfig;
pub use error::{I2pError, I2pResult};
pub use factory::I2pFactory;
pub use outbound::I2pOutbound;

/// Имя протокола в конфигурации; менять нельзя (стоит в файлах пользователей).
pub const PROTOCOL: &str = "i2p";
