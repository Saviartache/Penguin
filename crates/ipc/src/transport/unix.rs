//! Unix-сокет в файловой системе: путь, права и уборка чужого следа.
//!
//! Абстрактный сокет Linux открыт всем, а временный каталог macOS свой у
//! каждого пользователя, поэтому сокет лежит в каталоге с ограниченными правами.
//! Допускаются root, группа администраторов и один UID рабочего стола,
//! одобренный повышенным помощником; проверка peer-uid обязательна.

use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Group, Uid, User};
pub use tokio::net::UnixStream as Stream;

use super::classify;
use crate::error::{IpcError, IpcResult};

/// Каталог сокета: права на него ставятся до создания сокета.
const SYSTEM_DIR: &str = "/var/run/penguin";

const SOCKET_FILE: &str = "control.sock";

/// Одобренный UID может войти в каталог, но не перечислить и не заменить сокет.
const DIR_MODE: u32 = 0o751;

const SOCKET_MODE: u32 = 0o660;

/// Принимающая сторона; убирает файл сокета при закрытии.
pub struct Listener {
    inner: tokio::net::UnixListener,
    path: PathBuf,
}

impl Listener {
    /// Ждёт следующего клиента.
    pub async fn accept(&mut self) -> std::io::Result<Stream> {
        self.inner.accept().await.map(|(stream, _)| stream)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Открывает канал по указанному пути; отдельно от `listen` ради тестов.
pub fn listen_at(path: &Path) -> IpcResult<Listener> {
    prepare(path)?;
    clear_stale(path)?;
    restrict(path)?;

    let inner = tokio::net::UnixListener::bind(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrInUse => IpcError::AlreadyRunning,
        std::io::ErrorKind::PermissionDenied => IpcError::AccessDenied,
        _ => IpcError::Transport(format!("не удалось открыть канал управления: {e}")),
    })?;
    let listener = Listener {
        inner,
        path: path.to_owned(),
    };
    secure(path)?;
    Ok(listener)
}

/// Подключается к сокету и проверяет euid сервера: root для системного пути, иначе свой.
///
/// Владелец файла сокета сервера не удостоверяет.
pub async fn connect_at(path: &Path) -> IpcResult<Stream> {
    let stream = Stream::connect(path).await.map_err(classify)?;
    let expected = if is_system_path(path) {
        0
    } else {
        Uid::effective().as_raw()
    };
    crate::auth::check_server(&stream, expected)?;
    Ok(stream)
}

/// Где демон открывает канал: под root — общий каталог, иначе — свой
/// (для `penguin --foreground`). GUI ходит только в системный.
pub fn listen_path() -> PathBuf {
    if Uid::effective().is_root() {
        service_path()
    } else {
        user_path()
    }
}

/// Где искать канал, по порядку: служба, затем отладочный запуск.
pub fn connect_paths() -> Vec<PathBuf> {
    vec![service_path(), user_path()]
}

/// Подключается только к системному сокету, без запасного пути, даже под root.
pub async fn connect_service() -> IpcResult<Stream> {
    connect_at(&service_path()).await
}

pub(crate) fn service_path() -> PathBuf {
    PathBuf::from(SYSTEM_DIR).join(SOCKET_FILE)
}

pub(crate) fn is_system_path(path: &Path) -> bool {
    path == service_path()
}

/// Путь пользователя в своём подкаталоге: права ставятся на каталог.
fn user_path() -> PathBuf {
    let uid = Uid::effective().as_raw();
    if let Some(root) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
        && root.is_absolute()
        && let Ok(meta) = std::fs::symlink_metadata(&root)
        && meta.is_dir()
        && meta.uid() == uid
        && meta.mode() & 0o077 == 0
    {
        return root.join("penguin").join(SOCKET_FILE);
    }
    fallback_path(&std::env::temp_dir(), uid)
}

fn fallback_path(root: &Path, uid: u32) -> PathBuf {
    root.join(format!("penguin-{uid}")).join(SOCKET_FILE)
}

/// Заводит собственный каталог сокета и закрывает его от посторонних.
pub fn prepare(path: &Path) -> IpcResult<()> {
    let directory = path.parent().ok_or(IpcError::AccessDenied)?;
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    directory_handle(directory)?;
    Ok(())
}

fn directory_handle(directory: &Path) -> IpcResult<std::fs::File> {
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(directory)?;
    let meta = handle.metadata()?;
    if !crate::policy::protected_directory(
        meta.uid(),
        meta.mode(),
        meta.is_dir(),
        Uid::effective().as_raw(),
    ) {
        return Err(IpcError::AccessDenied);
    }
    Ok(handle)
}

/// Держит каталог закрытым на время bind/chown/chmod; вызывается после отказа живому слушателю.
pub(crate) fn restrict(path: &Path) -> IpcResult<()> {
    set_directory_mode(path, 0o700)
}

fn set_directory_mode(path: &Path, mode: u32) -> IpcResult<()> {
    directory_handle(path.parent().ok_or(IpcError::AccessDenied)?)?
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Убирает сокет упавшего демона; `Err(AlreadyRunning)` — сокет живой.
pub fn clear_stale(path: &Path) -> IpcResult<()> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
    use std::os::fd::AsRawFd;

    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    if !meta.file_type().is_socket() {
        return Err(IpcError::AccessDenied);
    }
    // Полная очередь означает живого слушателя; блокирующая проба могла бы зависнуть.
    let probe = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(std::io::Error::from)?;
    // Darwin не знает SOCK_NONBLOCK при создании.
    nix::fcntl::fcntl(
        &probe,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )
    .map_err(std::io::Error::from)?;
    let address = UnixAddr::new(path).map_err(std::io::Error::from)?;
    match connect(probe.as_raw_fd(), &address) {
        Ok(()) | Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINPROGRESS) => {
            Err(IpcError::AlreadyRunning)
        }
        Err(nix::errno::Errno::ECONNREFUSED) => {
            std::fs::remove_file(path)?;
            Ok(())
        }
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(err) => Err(std::io::Error::from(err).into()),
    }
}

/// Ставит права открытому сокету и его каталогу.
pub fn secure(path: &Path) -> IpcResult<()> {
    let system = is_system_path(path);
    if system {
        if !Uid::effective().is_root() {
            return Err(IpcError::AccessDenied);
        }
        let owner = crate::controller::approved()?.unwrap_or(0);
        let group = administrators().unwrap_or(Gid::from_raw(0));
        nix::unistd::chown(path, Some(Uid::from_raw(owner)), Some(group))
            .map_err(std::io::Error::from)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
        .map_err(|e| IpcError::Transport(format!("{}: {e}", path.display())))?;
    set_directory_mode(path, if system { DIR_MODE } else { 0o700 })
}

/// Группа администраторов системы.
pub fn administrators() -> Option<Gid> {
    ADMIN_GROUPS
        .iter()
        .find_map(|name| Group::from_name(name).ok().flatten())
        .map(|group| group.gid)
}

/// В macOS администраторы сидят в `admin`, а не в `wheel`.
#[cfg(target_os = "macos")]
const ADMIN_GROUPS: &[&str] = &["admin"];

/// Debian и потомки — `sudo`, Fedora, Arch и SUSE — `wheel`.
#[cfg(not(target_os = "macos"))]
const ADMIN_GROUPS: &[&str] = &["sudo", "wheel"];

/// Вправе ли пользователь администрировать машину.
///
/// Основная группа в списке членов не значится, а список членов не всегда полон.
pub fn is_administrator(uid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let Some(admins) = administrators() else {
        return false;
    };
    let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid)) else {
        return false;
    };

    if user.gid == admins {
        return true;
    }
    if let Ok(Some(group)) = Group::from_gid(admins)
        && group.mem.contains(&user.name)
    {
        return true;
    }
    in_supplementary_groups(&user, admins)
}

/// Есть ли группа среди дополнительных групп пользователя.
#[cfg(not(target_os = "macos"))]
fn in_supplementary_groups(user: &User, group: Gid) -> bool {
    let Ok(name) = std::ffi::CString::new(user.name.as_str()) else {
        return false;
    };
    nix::unistd::getgrouplist(&name, user.gid)
        .map(|groups| groups.contains(&group))
        .unwrap_or(false)
}

/// В macOS `getgrouplist` в `nix` нет; членов `admin` система держит в самой группе.
#[cfg(target_os = "macos")]
fn in_supplementary_groups(_user: &User, _group: Gid) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socket_lives_inside_its_own_directory() {
        let path = PathBuf::from(SYSTEM_DIR).join(SOCKET_FILE);
        assert_eq!(path.parent(), Some(Path::new(SYSTEM_DIR)));
    }

    #[test]
    fn others_can_only_traverse_the_directory() {
        assert_eq!(DIR_MODE & 0o007, 1);
        assert_eq!(DIR_MODE & 0o022, 0);
        assert_eq!(SOCKET_MODE & 0o007, 0);
    }

    #[test]
    fn the_system_path_is_tried_first() {
        let paths = connect_paths();
        assert!(paths[0].starts_with(SYSTEM_DIR), "{paths:?}");
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn service_target_is_fixed_and_not_a_per_user_endpoint() {
        let service = service_path();
        assert_eq!(service, Path::new("/var/run/penguin/control.sock"));
        assert!(is_system_path(&service));
        for uid in [0, 501, 1000] {
            let foreground = fallback_path(Path::new("/tmp"), uid);
            assert_ne!(service, foreground);
            assert!(!is_system_path(&foreground));
        }
    }

    #[test]
    fn an_ordinary_user_gets_a_path_of_their_own() {
        if Uid::effective().is_root() {
            assert!(is_system_path(&listen_path()));
        } else {
            assert_eq!(listen_path(), user_path());
        }
    }

    #[test]
    fn fallback_is_uid_specific() {
        assert_ne!(
            fallback_path(Path::new("/tmp"), 1000),
            fallback_path(Path::new("/tmp"), 1001)
        );
        assert_eq!(
            fallback_path(Path::new("/tmp"), 501),
            Path::new("/tmp/penguin-501/control.sock")
        );
    }

    #[test]
    fn we_are_an_administrator_or_we_are_not_but_asking_does_not_panic() {
        // Вызывается на каждое подключение.
        let _ = is_administrator(nix::unistd::getuid().as_raw());
        assert!(!is_administrator(u32::MAX - 1));
    }
}
