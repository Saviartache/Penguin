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
//! Тому же, кому можно на Windows (`transport::windows`): системе, администраторам
//! и вошедшему пользователю. Здесь это выражается членством в группе
//! администраторов — то есть теми, кто и так может стать суперпользователем.
//! Разрешить им говорить с демоном не значит дать что-то новое.

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

/// Права каталога: суперпользователь и администраторы, больше никто.
const DIR_MODE: u32 = 0o750;

/// Права сокета внутри каталога.
const SOCKET_MODE: u32 = 0o660;

/// Где демон открывает канал.
///
/// Под суперпользователем — общий каталог, до которого дотянется окно
/// пользователя. Иначе — свой каталог: так `penguin --foreground`, запущенный
/// человеком для отладки, работает без всяких прав, и окно того же человека
/// его находит.
pub fn listen_path() -> PathBuf {
    if Uid::effective().is_root() {
        PathBuf::from(SYSTEM_DIR).join(SOCKET_FILE)
    } else {
        user_path()
    }
}

/// Где искать канал, по порядку.
///
/// Сначала общий: почти всегда демон — это служба. Потом свой — на случай
/// отладочного запуска.
pub fn connect_paths() -> Vec<PathBuf> {
    vec![PathBuf::from(SYSTEM_DIR).join(SOCKET_FILE), user_path()]
}

/// Путь в каталоге текущего пользователя.
///
/// Тоже в своём подкаталоге: права ставятся на каталог, и ставить их на общий
/// временный — значит закрыть его всем остальным программам.
fn user_path() -> PathBuf {
    // `XDG_RUNTIME_DIR` в Linux и `TMPDIR` в macOS — оба свои у каждого
    // пользователя, и оба уже закрыты от чужих.
    let root = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    root.join("penguin").join(SOCKET_FILE)
}

/// Заводит каталог сокета и закрывает его от посторонних.
///
/// Каталог у сокета **свой**: права ставятся на него целиком, и путь без
/// собственного каталога закрыл бы чужой — общий временный, например.
pub fn prepare(path: &Path) -> IpcResult<()> {
    let Some(directory) = path.parent() else {
        return Ok(());
    };

    std::fs::create_dir_all(directory)
        .map_err(|e| IpcError::Transport(format!("{}: {e}", directory.display())))?;

    // Права выставляются и на уже существующий каталог: он мог остаться от
    // прошлой версии, и щедрые права на нём — это открытый канал управления.
    set_mode(directory, DIR_MODE)?;

    // Группа администраторов нужна только общему каталогу: свой и так закрыт
    // тем, что лежит в каталоге пользователя.
    if Uid::effective().is_root() {
        match administrators() {
            Some(group) => nix::unistd::chown(directory, Some(Uid::from_raw(0)), Some(group))
                .map_err(|e| IpcError::Transport(format!("{}: {e}", directory.display())))?,
            // Машина без группы администраторов — случай редкий, и молчать о
            // нём нельзя: окно не сможет подключиться к службе.
            None => tracing::error!(
                "в системе нет группы администраторов — окно не дотянется до службы"
            ),
        }
    }
    Ok(())
}

/// Убирает сокет, оставшийся от упавшего демона.
///
/// `Err(AlreadyRunning)` — сокет живой, и демон за ним отвечает.
pub fn clear_stale(path: &Path) -> IpcResult<()> {
    if !path.exists() {
        return Ok(());
    }

    // Единственный надёжный способ отличить живой сокет от брошенного —
    // попробовать подключиться. Файл остаётся на месте и после смерти демона,
    // и по нему не видно ничего.
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(IpcError::AlreadyRunning);
    }

    std::fs::remove_file(path).map_err(|e| IpcError::Transport(format!("{}: {e}", path.display())))
}

/// Ограничивает права уже открытого сокета.
///
/// Каталог закрыт и без этого; права файла — второй рубеж на случай, если
/// каталог кто-то откроет.
pub fn secure(path: &Path) -> IpcResult<()> {
    set_mode(path, SOCKET_MODE)?;

    if Uid::effective().is_root()
        && let Some(group) = administrators()
    {
        nix::unistd::chown(path, Some(Uid::from_raw(0)), Some(group))
            .map_err(|e| IpcError::Transport(format!("{}: {e}", path.display())))?;
    }
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
    fn the_directory_is_closed_to_others() {
        // Последняя цифра — права «всех остальных». Ненулевая означает канал
        // управления, открытый любому процессу в системе.
        assert_eq!(DIR_MODE & 0o007, 0);
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
    fn an_ordinary_user_gets_a_path_of_their_own() {
        // Иначе `penguin --foreground` для отладки требовал бы прав, которых
        // у отладки нет.
        assert_eq!(listen_path(), user_path(), "тест идёт не от root");
    }

    #[test]
    fn the_system_has_a_group_of_administrators() {
        // Без неё окно не дотянется до службы, и знать об этом надо здесь, а
        // не по молчаливому отказу в подключении.
        assert!(administrators().is_some());
    }

    #[test]
    fn we_are_an_administrator_or_we_are_not_but_asking_does_not_panic() {
        // Вызывается на каждое подключение к каналу управления.
        let _ = is_administrator(nix::unistd::getuid().as_raw());
        // Несуществующий пользователь администратором быть не может.
        assert!(!is_administrator(u32::MAX - 1));
    }
}
