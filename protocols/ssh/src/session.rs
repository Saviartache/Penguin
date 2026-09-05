//! Одно соединение SSH: рукопожатие, отпечаток хоста, опознание.
//!
//! Дальше в дело вступает `russh`: он сам ведёт фоновую задачу, которая
//! читает и пишет сокет и раскладывает данные по каналам. `Link` не заводит
//! собственных задач и не разбирает кадры — держит только готовое соединение
//! ([`russh::client::Handle`]) и умеет открыть на нём канал `direct-tcpip`.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use penguin_core::address::{Address, SocketAddress};
use penguin_proto::connect;
use penguin_proto::dialer::Dialer;
use russh::client::{self, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelOpenFailure, Disconnect};

use crate::config::SshConfig;
use crate::error::{SshError, SshResult};
use crate::fingerprint::HostFingerprint;

/// Как часто напоминать о себе, пока соединение простаивает.
///
/// Без этого NAT забывает отображение через минуту-другую, и обрыв
/// обнаруживается только следующей попыткой открыть канал.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// Соединение SSH вместе с тем, чем оно опозналось.
pub struct Link {
    handle: Handle<ClientHandler>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("closed", &self.handle.is_closed())
            .finish()
    }
}

impl Link {
    /// Поднимает соединение, проверяет отпечаток хоста и опознаётся.
    pub async fn connect(
        config: &SshConfig,
        host: &Address,
        port: u16,
        dialer: &dyn Dialer,
    ) -> SshResult<Arc<Self>> {
        let tcp = connect::dial(dialer, host, port)
            .await
            .map_err(|e| SshError::disconnected(e.to_string()))?;

        let expected = config.host_fingerprint()?;
        let mismatch: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let handler = ClientHandler {
            expected,
            mismatch: Arc::clone(&mismatch),
        };

        let ssh_config = Arc::new(client::Config {
            keepalive_interval: Some(KEEPALIVE),
            ..client::Config::default()
        });

        let handshake = penguin_transport::deadline::handshake("рукопожатие SSH", async {
            client::connect_stream(ssh_config, tcp, handler).await
        })
        .await;

        let mut handle = match handshake {
            Ok(handle) => handle,
            // Общая ошибка (`russh` не различает «мы отвергли ключ» и любой
            // другой сбой рукопожатия) заменяется точной, если это была
            // именно она: иначе несовпадение выглядело бы обрывом сети.
            Err(err) => return Err(take_mismatch(&mismatch).unwrap_or(err)),
        };

        authenticate(&mut handle, config).await?;
        Ok(Arc::new(Self { handle }))
    }

    /// Годится ли соединение под новый канал.
    pub fn usable(&self) -> bool {
        !self.handle.is_closed()
    }

    /// Открывает канал `direct-tcpip` до цели.
    ///
    /// Имя пишется как есть, без разрешения на этой стороне: сервер обязан
    /// уметь его сам, и наш `remote_dns` в `Capabilities` это обещает.
    pub async fn open_channel(&self, target: &SocketAddress) -> SshResult<Channel<client::Msg>> {
        let host_to_connect = match &target.host {
            Address::Domain(domain) => domain.clone(),
            // Без квадратных скобок: это поле протокола SSH, а не запись
            // `host:port`, и скобки вокруг IPv6 сервер бы не понял.
            Address::Ip(ip) => ip.to_string(),
        };

        self.handle
            .channel_open_direct_tcpip(host_to_connect, u32::from(target.port), "127.0.0.1", 0)
            .await
            .map_err(classify_channel_open)
    }

    /// Закрывает соединение.
    pub async fn close(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await;
    }
}

/// Опознаётся паролем или ключом — ровно одним, как того требует [`SshConfig::validate`].
async fn authenticate(handle: &mut Handle<ClientHandler>, config: &SshConfig) -> SshResult<()> {
    penguin_transport::deadline::handshake("опознание SSH", async {
        let result = if let Some(key) = config.private_key()? {
            // Хэш для RSA стоит спросить у сервера: часть современных
            // серверов больше не принимает устаревший `ssh-rsa` (SHA-1), а
            // для остальных алгоритмов запрос ничего не меняет.
            let hash_alg = if key.algorithm().is_rsa() {
                // `Ok(None)` — сервер не прислал расширение, `Ok(Some(None))`
                // — прислал, но `rsa-sha2-*` не назвал: в обоих случаях
                // остаётся только устаревший `ssh-rsa`, то есть `None`.
                handle
                    .best_supported_rsa_hash()
                    .await
                    .ok()
                    .flatten()
                    .flatten()
            } else {
                None
            };
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            handle
                .authenticate_publickey(config.username.as_str(), key)
                .await?
        } else {
            let password = config.password.as_deref().unwrap_or_default();
            handle
                .authenticate_password(config.username.as_str(), password)
                .await?
        };

        if result.success() {
            Ok(())
        } else {
            Err(SshError::AuthRejected)
        }
    })
    .await
}

/// Переводит отказ в открытии канала на язык протокола.
fn classify_channel_open(err: russh::Error) -> SshError {
    match &err {
        russh::Error::ChannelOpenFailure(reason) => {
            SshError::ChannelRefused(describe_channel_failure(reason.clone()))
        }
        _ => SshError::from(err),
    }
}

/// Текст причины отказа — коды по RFC 4254, §5.1.
fn describe_channel_failure(reason: ChannelOpenFailure) -> String {
    match reason {
        ChannelOpenFailure::AdministrativelyProhibited => "запрещено администратором".to_owned(),
        ChannelOpenFailure::ConnectFailed => "сервер не смог подключиться к цели".to_owned(),
        ChannelOpenFailure::UnknownChannelType => "сервер не понял тип канала".to_owned(),
        ChannelOpenFailure::ResourceShortage => "серверу не хватило ресурсов".to_owned(),
        // Код вне RFC 4254. Разбор здесь полный, без ветки «всё остальное»:
        // перечисление в `russh` открыто к расширению не объявлено, и новый
        // код причины лучше поймать сборкой, чем показать человеку `Debug`.
        ChannelOpenFailure::Other { code, reason } => format!("код {code}: {reason}"),
    }
}

/// Забирает причину несовпадения ключа, если проверка её записала.
fn take_mismatch(mismatch: &StdMutex<Option<String>>) -> Option<SshError> {
    lock(mismatch).take().map(SshError::HostKeyMismatch)
}

/// Берёт замок, не роняя соединение из-за чужой паники (`AGENTS.md` §4.3).
fn lock<T>(what: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match what.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Обработчик клиента `russh`: единственная обязанность — сверить ключ хоста.
///
/// Остальные методы [`client::Handler`] оставлены по умолчанию: банер
/// опознания показывать некому, а серверные запросы, на которые клиент не
/// подписывался (переадресация портов и подобное), здесь не нужны.
struct ClientHandler {
    expected: HostFingerprint,
    /// Сюда пишется отпечаток, который прислал сервер, если он не совпал.
    /// `check_server_key` не может вернуть свою ошибку содержательно: после
    /// `Ok(false)` `russh` сам обрывает рукопожатие своей общей ошибкой, и
    /// без этой ячейки причина терялась бы.
    mismatch: Arc<StdMutex<Option<String>>>,
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> SshResult<bool> {
        let key = server_public_key.public_key();
        if self.expected.matches(&key) {
            return Ok(true);
        }
        *lock(&self.mismatch) = Some(key.fingerprint(HashAlg::Sha256).to_string());
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_channel_open_failure_is_told_apart_from_a_broken_link() {
        // Ради этого различия и стоило искать в `russh` подходящий вариант:
        // без него любой отказ выглядел бы обрывом сети.
        let refused = classify_channel_open(russh::Error::ChannelOpenFailure(
            ChannelOpenFailure::AdministrativelyProhibited,
        ));
        assert!(matches!(refused, SshError::ChannelRefused(_)));

        let other = classify_channel_open(russh::Error::Disconnect);
        assert!(matches!(other, SshError::Ssh(_)));
    }

    #[test]
    fn a_recorded_mismatch_overrides_the_generic_error() {
        let mismatch = StdMutex::new(Some("SHA256:чужой".to_owned()));
        let err = take_mismatch(&mismatch).expect("причина записана");
        assert!(matches!(err, SshError::HostKeyMismatch(text) if text == "SHA256:чужой"));
        assert!(lock(&mismatch).is_none(), "причина не забралась один раз");
    }

    #[test]
    fn no_recorded_mismatch_means_none() {
        let mismatch = StdMutex::new(None);
        assert!(take_mismatch(&mismatch).is_none());
    }
}
