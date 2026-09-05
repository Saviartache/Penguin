//! Unix-сокет: где он лежит, кто до него дотянется и как убрать чужой след.
//!
//! Общая часть — открытие и подключение — живёт в [`super`]; здесь то, чего
//! на Windows нет.
//!
//! # Почему не безымянный сокет
//!
//! У `interprocess` есть «пространство имён»: на Linux это абстрактный сокет,
//! у которого нет прав вовсе, на macOS — файл во временном каталоге. Ни то ни
//! другое не годится. Временный каталог в macOS **свой у каждого
//! пользователя**: демон под системной учётной записью и окно под человеком
//! просто не нашли бы друг друга. Абстрактный сокет в Linux, наоборот, открыт
//! всем без исключения — а через канал управления выключается kill switch.
//!
//! Поэтому сокет лежит в файловой системе, а доступ к нему ограничен правами
//! каталога.
//!
//! # Кому можно
//!
//! Root, the selected administrator group, and the exact desktop UID approved
//! by the elevated helper. Socket ownership grants that UID access even when
//! it is not a member of the selected group. Peer credentials remain mandatory.

use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::{Gid, Group, Uid, User};

use crate::error::{IpcError, IpcResult};

/// Каталог, в котором живёт сокет.
///
/// Каталог, а не файл рядом с другими: права на него и есть первый рубеж, и
/// выставляются они **до** создания сокета. Права самого файла сокета
/// пришлось бы менять уже после привязки, а между привязкой и правкой сокет
/// открыт всем.
const SYSTEM_DIR: &str = "/var/run/penguin";

/// Имя файла сокета.
const SOCKET_FILE: &str = "control.sock";

/// The approved UID may traverse, but cannot list or replace socket entries.
const DIR_MODE: u32 = 0o751;

/// Права сокета внутри каталога.
const SOCKET_MODE: u32 = 0o660;

/// Где демон открывает канал.
///
/// Под суперпользователем — общий каталог, до которого дотянется окно
/// пользователя. Иначе — свой каталог: так `penguin --foreground`, запущенный
/// человеком для отладки, работает без всяких прав, и CLI того же человека
/// его находит. GUI must use only the system service endpoint.
pub fn listen_path() -> PathBuf {
    if Uid::effective().is_root() {
        service_path()
    } else {
        user_path()
    }
}

/// Где искать канал, по порядку.
///
/// Сначала общий: почти всегда демон — это служба. Потом свой — на случай
/// отладочного запуска.
pub fn connect_paths() -> Vec<PathBuf> {
    vec![service_path(), user_path()]
}

/// Connects only to the system socket and verifies the server's effective UID.
///
/// There is no per-user fallback, including for root readiness probes.
pub async fn connect_service() -> IpcResult<interprocess::local_socket::tokio::Stream> {
    super::connect_at(&service_path()).await
}

pub(crate) fn service_path() -> PathBuf {
    PathBuf::from(SYSTEM_DIR).join(SOCKET_FILE)
}

pub(crate) fn is_system_path(path: &Path) -> bool {
    path == service_path()
}

/// Путь в каталоге текущего пользователя.
///
/// Тоже в своём подкаталоге: права ставятся на каталог, и ставить их на общий
/// временный — значит закрыть его всем остальным программам.
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

/// Заводит каталог сокета и закрывает его от посторонних.
///
/// Каталог у сокета **свой**: права ставятся на него целиком, и путь без
/// собственного каталога закрыл бы чужой — общий временный, например.
pub fn prepare(path: &Path) -> IpcResult<()> {
    let directory = path.parent().ok_or(IpcError::AccessDenied)?;
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    let _ = directory_handle(directory)?;
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

pub(crate) fn restrict(path: &Path) -> IpcResult<()> {
    // Only after rejecting a live listener: a second daemon must not change
    // its permissions. Keep the directory private across bind/chown/chmod.
    directory_handle(path.parent().ok_or(IpcError::AccessDenied)?)?
        .set_permissions(std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Убирает сокет, оставшийся от упавшего демона.
///
/// `Err(AlreadyRunning)` — сокет живой, и демон за ним отвечает.
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
    // A full backlog is live, not stale. A blocking probe can hang startup.
    let probe = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(std::io::Error::from)?;
    // Darwin does not support SOCK_NONBLOCK at socket creation.
    nix::fcntl::fcntl(
        probe.as_raw_fd(),
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

/// Ограничивает права уже открытого сокета.
///
/// Каталог закрыт и без этого; права файла — второй рубеж на случай, если
/// каталог кто-то откроет.
pub fn secure(path: &Path) -> IpcResult<()> {
    if is_system_path(path) {
        if !Uid::effective().is_root() {
            return Err(IpcError::AccessDenied);
        }
        let owner = crate::controller::approved()?.unwrap_or(0);
        let group = administrators().unwrap_or(Gid::from_raw(0));
        nix::unistd::chown(path, Some(Uid::from_raw(owner)), Some(group))
            .map_err(std::io::Error::from)?;
    }
    set_mode(path, SOCKET_MODE)?;
    let mode = if is_system_path(path) {
        DIR_MODE
    } else {
        0o700
    };
    directory_handle(path.parent().ok_or(IpcError::AccessDenied)?)?
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Ставит права файлу или каталогу.
fn set_mode(path: &Path, mode: u32) -> IpcResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| IpcError::Transport(format!("{}: {e}", path.display())))
}

/// Группа администраторов системы.
///
/// Имя у неё своё в каждой системе, и угадывать его списком «на все случаи»
/// нельзя: в macOS есть и `wheel`, но состоит он из одного суперпользователя,
/// а администраторы машины сидят в `admin`.
pub fn administrators() -> Option<Gid> {
    for name in ADMIN_GROUPS {
        if let Ok(Some(group)) = Group::from_name(name) {
            return Some(group.gid);
        }
    }
    None
}

/// Как называется группа администраторов.
#[cfg(target_os = "macos")]
const ADMIN_GROUPS: &[&str] = &["admin"];

/// Как называется группа администраторов.
///
/// Две: в Debian и её потомках это `sudo`, в Fedora, Arch и SUSE — `wheel`.
#[cfg(not(target_os = "macos"))]
const ADMIN_GROUPS: &[&str] = &["sudo", "wheel"];

/// Вправе ли пользователь администрировать машину.
///
/// Спрашивается несколькими способами, потому что ни один не отвечает верно
/// сам по себе: основная группа в списке членов не значится, а список членов
/// не всегда полон.
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
///
/// Отдельно, потому что спросить об этом можно не везде: в macOS
/// `getgrouplist` из `nix` нет, а список членов группы `admin` система
/// заполняет сама — и его хватает.
#[cfg(not(target_os = "macos"))]
fn in_supplementary_groups(user: &User, group: Gid) -> bool {
    let Ok(name) = std::ffi::CString::new(user.name.as_str()) else {
        return false;
    };
    nix::unistd::getgrouplist(&name, user.gid)
        .map(|groups| groups.contains(&group))
        .unwrap_or(false)
}

/// Есть ли группа среди дополнительных групп пользователя.
#[cfg(target_os = "macos")]
fn in_supplementary_groups(_user: &User, _group: Gid) -> bool {
    // Спросить нечем, но и незачем: членство в `admin` система держит в
    // списке членов самой группы, а его мы уже прочитали.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socket_lives_inside_its_own_directory() {
        // Каталог и есть первый рубеж: права на него ставятся до того, как
        // сокет появится.
        let path = PathBuf::from(SYSTEM_DIR).join(SOCKET_FILE);
        assert_eq!(path.parent(), Some(Path::new(SYSTEM_DIR)));
    }

    #[test]
    fn others_can_only_traverse_the_directory() {
        // Traversal lets the approved socket owner connect, not replace it.
        assert_eq!(DIR_MODE & 0o007, 1);
        assert_eq!(DIR_MODE & 0o022, 0);
        assert_eq!(SOCKET_MODE & 0o007, 0);
    }

    #[test]
    fn the_system_path_is_tried_first() {
        // Демон почти всегда служба; свой каталог — только для отладочного
        // запуска, и искать в нём раньше значило бы подключаться не к тому.
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
        // Иначе `penguin --foreground` для отладки требовал бы прав, которых
        // у отладки нет.
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
        // Вызывается на каждое подключение к каналу управления.
        let _ = is_administrator(nix::unistd::getuid().as_raw());
        // Несуществующий пользователь администратором быть не может.
        assert!(!is_administrator(u32::MAX - 1));
    }
}
