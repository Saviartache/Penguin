//! Запуск и остановка i2pd вместе с тоннелем.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use penguin_proto::outbound::Outbound;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::bypass::{self, Admitted};
use crate::conf::{self, HTTP_PROXY};
use crate::error::{I2pdError, I2pdResult};
use crate::install;

/// Сколько ждать HTTP-прокси: i2pd открывает его только после reseed, а тот
/// при отказе узла ждёт 30 с до следующего круга.
const READY: Duration = Duration::from_secs(90);
const POLL: Duration = Duration::from_millis(200);

/// Запущенный i2pd и его обход тоннеля (гаснет вместе с записью).
struct Running {
    child: Child,
    _bypass: DropGuard,
}

/// i2pd службы: файл, данные и журнал — в `home`.
pub struct Sidecar {
    home: PathBuf,
    running: Mutex<Option<Running>>,
}

impl std::fmt::Debug for Sidecar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sidecar")
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl Sidecar {
    /// i2pd в каталоге `home`; ничего не запускает.
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            running: Mutex::new(None),
        }
    }

    /// Каталог i2pd.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Ставит присланный файл; запущенный i2pd подхватит его при следующем подключении.
    pub fn install(&self, bytes: &[u8]) -> I2pdResult<()> {
        install::install(&self.home, bytes)
    }

    /// Запускает i2pd, если он не работает; `direct` — выход мимо тоннеля.
    pub async fn start(&self, direct: Arc<dyn Outbound>) -> I2pdResult<()> {
        let mut running = self.running.lock().await;
        if let Some(current) = running.as_mut() {
            if matches!(current.child.try_wait(), Ok(None)) {
                return Ok(());
            }
            *running = None;
        }

        let binary = install::check(&self.home)?;
        #[cfg(unix)]
        let account = Some(crate::account::unprivileged()?);
        #[cfg(not(unix))]
        let account = None;
        let data = self.home.join("data");
        prepare_data(&data, account)?;

        let cancel = CancellationToken::new();
        // Ошибка или отмена подключения на любом шаге гасит обход.
        let bypass = cancel.clone().drop_guard();
        let admitted = Arc::new(Admitted::default());
        let owners = Arc::from(penguin_process::resolver::system_resolver());
        let via = bypass::start(direct, owners, Arc::clone(&admitted), cancel).await?;

        let config = data.join("i2pd.conf");
        std::fs::write(&config, conf::render(via)).map_err(|err| I2pdError::io(&config, err))?;
        let log = data.join("i2pd.log");

        // `kill_on_drop`: отменённый запуск не оставит процесса.
        let mut child = command(&binary, &data, &config, &log, account)
            .spawn()
            .map_err(|err| I2pdError::io(&binary, err))?;
        if let Some(pid) = child.id() {
            admitted.set(pid);
        }
        tracing::info!(pid = child.id(), bypass = %via, "i2pd запущен");

        wait_ready(&mut child, &log).await?;
        *running = Some(Running {
            child,
            _bypass: bypass,
        });
        Ok(())
    }

    /// Останавливает i2pd; не запущен — не ошибка.
    pub async fn stop(&self) {
        let Some(mut running) = self.running.lock().await.take() else {
            return;
        };
        if let Err(err) = running.child.kill().await {
            tracing::debug!(%err, "i2pd уже завершился");
        }
        tracing::info!("i2pd остановлен");
    }
}

/// `uid` и `gid`, от которых работает i2pd; `None` — от учётной записи службы.
type Account = Option<(u32, u32)>;

/// Каталог данных: его пишет i2pd, а он работает не от root.
fn prepare_data(data: &Path, account: Account) -> I2pdResult<()> {
    std::fs::create_dir_all(data).map_err(|err| I2pdError::io(data, err))?;
    #[cfg(unix)]
    if let Some((uid, gid)) = account {
        std::os::unix::fs::chown(data, Some(uid), Some(gid))
            .map_err(|err| I2pdError::io(data, err))?;
    }
    #[cfg(not(unix))]
    let _ = account;
    Ok(())
}

fn command(binary: &Path, data: &Path, config: &Path, log: &Path, account: Account) -> Command {
    let mut command = Command::new(binary);
    command
        .arg(format!("--datadir={}", data.display()))
        .arg(format!("--conf={}", config.display()))
        .arg(format!("--logfile={}", log.display()))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // Служба упала — i2pd не должен держать порт.
        .kill_on_drop(true);
    #[cfg(unix)]
    if let Some((uid, gid)) = account {
        command.uid(uid).gid(gid);
    }
    #[cfg(not(unix))]
    let _ = account;
    command
}

/// Ждёт, пока HTTP-прокси примет соединение, или выхода процесса.
async fn wait_ready(child: &mut Child, log: &Path) -> I2pdResult<()> {
    let deadline = tokio::time::Instant::now() + READY;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(I2pdError::Exited(status.to_string(), log.to_path_buf()));
        }
        if TcpStream::connect(HTTP_PROXY).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(POLL).await;
    }
    Err(I2pdError::NotReady(READY.as_secs(), log.to_path_buf()))
}
