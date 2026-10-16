//! Linux: перечисление и сброс сокетов через `sock_diag` (то же делает `ss -K`).

use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType};

use super::sock_diag::{
    ID_LEN, LIVE_STATES, NLM_F_ACK, NLM_F_DUMP, Reply, SOCK_DESTROY, SOCK_DIAG_BY_FAMILY, SocketId,
    remote_of, replies, request,
};
use crate::error::{PlatformError, PlatformResult};

/// Буфер ответа: перечисление приходит частями такого размера.
const BUFFER: usize = 32 * 1024;

pub(super) fn reset_tcp(selected: &dyn Fn(SocketAddrV4) -> bool) -> PlatformResult<usize> {
    let socket = nix::sys::socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )
    .map_err(|err| failure("сокет sock_diag", err))?;

    let targets: Vec<SocketId> = live_sockets(&socket)?
        .into_iter()
        .filter(|id| selected(remote_of(id)))
        .collect();

    let mut reset = 0;
    for id in &targets {
        if destroy(&socket, id)? {
            reset += 1;
        }
    }
    Ok(reset)
}

/// Установленные и устанавливаемые соединения TCP поверх IPv4.
fn live_sockets(socket: &OwnedFd) -> PlatformResult<Vec<SocketId>> {
    send(
        socket,
        &request(SOCK_DIAG_BY_FAMILY, NLM_F_DUMP, LIVE_STATES, &[0; ID_LEN]),
    )?;

    let mut found = Vec::new();
    let mut buffer = vec![0u8; BUFFER];
    loop {
        let read = nix::sys::socket::recv(socket.as_raw_fd(), &mut buffer, MsgFlags::empty())
            .map_err(|err| failure("перечисление сокетов", err))?;
        if read == 0 {
            return Ok(found);
        }
        for reply in replies(&buffer[..read]) {
            match reply {
                Reply::Socket(id) => found.push(id),
                Reply::Done => return Ok(found),
                Reply::Status(code) if code < 0 => return Err(kernel_error(code)),
                Reply::Status(_) | Reply::Other => {}
            }
        }
    }
}

/// Сбрасывает один сокет; `false` — он закрылся сам, пока до него дошла очередь.
fn destroy(socket: &OwnedFd, id: &SocketId) -> PlatformResult<bool> {
    send(socket, &request(SOCK_DESTROY, NLM_F_ACK, u32::MAX, id))?;

    let mut buffer = [0u8; 512];
    let read = nix::sys::socket::recv(socket.as_raw_fd(), &mut buffer, MsgFlags::empty())
        .map_err(|err| failure("сброс сокета", err))?;
    match replies(&buffer[..read]).first() {
        Some(Reply::Status(0)) => Ok(true),
        Some(Reply::Status(code)) if -code == libc::ENOENT => Ok(false),
        Some(Reply::Status(code)) => Err(kernel_error(*code)),
        _ => Err(PlatformError::Route(
            "ядро не подтвердило сброс сокета".to_owned(),
        )),
    }
}

fn send(socket: &OwnedFd, message: &[u8]) -> PlatformResult<()> {
    nix::sys::socket::send(socket.as_raw_fd(), message, MsgFlags::empty())
        .map(|_| ())
        .map_err(|err| failure("запрос sock_diag", err))
}

fn kernel_error(code: i32) -> PlatformError {
    match -code {
        libc::EPERM | libc::EACCES => PlatformError::PermissionDenied("сброс сокетов".to_owned()),
        // Ядро собрано без CONFIG_INET_DIAG_DESTROY.
        libc::EOPNOTSUPP => PlatformError::Unsupported("сброс сокетов (CONFIG_INET_DIAG_DESTROY)"),
        errno => PlatformError::Route(std::io::Error::from_raw_os_error(errno).to_string()),
    }
}

fn failure(what: &str, err: nix::errno::Errno) -> PlatformError {
    PlatformError::Route(format!("{what}: {err}"))
}
