//! Настройка интерфейса через `ioctl`: адрес, маска, MTU, поднятие.
//!
//! Не через `ip`: адрес адаптера — то, без чего тоннель не работает вовсе, и
//! зависеть здесь от разбора вывода чужой программы (которой к тому же может
//! не быть в системе) нельзя.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};

use crate::error::{TunError, TunResult};

/// Длина имени интерфейса вместе с завершающим нулём.
const NAME_LEN: usize = 16;

/// Запрос к интерфейсу: имя и одно поле по смыслу команды.
///
/// Разложен байтами, а не объединением: объединение потребовало бы `unsafe`
/// на каждое чтение поля, а нужно нам всего три раскладки — адрес, число и
/// флаги.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(super) struct IfReq {
    name: [u8; NAME_LEN],
    data: [u8; 24],
}

impl IfReq {
    /// Пустой запрос к интерфейсу с таким именем.
    ///
    /// Имя длиннее пятнадцати байт система не примет; обрезать его молча
    /// нельзя — обрезанное имя означает настройку **чужого** интерфейса.
    pub(super) fn new(name: &str) -> TunResult<Self> {
        let bytes = name.as_bytes();
        if bytes.len() >= NAME_LEN {
            return Err(TunError::adapter(
                name,
                format!("имя длиннее {} байт", NAME_LEN - 1),
            ));
        }

        let mut request = Self {
            name: [0; NAME_LEN],
            data: [0; 24],
        };
        request.name[..bytes.len()].copy_from_slice(bytes);
        Ok(request)
    }

    /// Имя, как его вернула система.
    pub(super) fn name(&self) -> String {
        let end = self.name.iter().position(|byte| *byte == 0).unwrap_or(0);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    /// Кладёт в поле данных флаги адаптера (`TUNSETIFF`, `SIOCSIFFLAGS`).
    pub(super) fn with_flags(mut self, flags: i16) -> Self {
        self.data[..2].copy_from_slice(&flags.to_ne_bytes());
        self
    }

    /// Флаги из поля данных.
    pub(super) fn flags(&self) -> i16 {
        i16::from_ne_bytes([self.data[0], self.data[1]])
    }

    /// Кладёт в поле данных число (`SIOCSIFMTU`).
    pub(super) fn with_number(mut self, value: i32) -> Self {
        self.data[..4].copy_from_slice(&value.to_ne_bytes());
        self
    }

    /// Кладёт в поле данных адрес IPv4 в виде `sockaddr_in`.
    pub(super) fn with_address(mut self, address: Ipv4Addr) -> Self {
        // Раскладка `sockaddr_in`: семейство, порт, адрес. Порт остаётся
        // нулевым — у интерфейса его нет.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "семейство адресов не выходит за пределы u16"
        )]
        let family = (libc::AF_INET as u16).to_ne_bytes();
        self.data[..2].copy_from_slice(&family);
        self.data[4..8].copy_from_slice(&address.octets());
        self
    }
}

/// Команды, которыми настраивается интерфейс.
///
/// Числа заданы в `<linux/sockios.h>` и не меняются: на них держится двоичная
/// совместимость ядра с программами, собранными десятилетия назад.
pub(super) mod request {
    /// Создать или занять адаптер `tun`. `_IOW('T', 202, int)`.
    pub(in super::super) const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
    /// Задать адрес интерфейса.
    pub(super) const SIOCSIFADDR: libc::c_ulong = 0x8916;
    /// Задать маску подсети.
    pub(super) const SIOCSIFNETMASK: libc::c_ulong = 0x891C;
    /// Прочитать флаги.
    pub(super) const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    /// Задать флаги.
    pub(super) const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    /// Задать MTU.
    pub(super) const SIOCSIFMTU: libc::c_ulong = 0x8922;
}

/// Выполняет `ioctl` над запросом к интерфейсу.
pub(super) fn ioctl(fd: &OwnedFd, request: libc::c_ulong, argument: &mut IfReq) -> TunResult<()> {
    #[allow(unsafe_code, reason = "настройка интерфейса через ioctl")]
    let code = unsafe { libc::ioctl(fd.as_raw_fd(), request, std::ptr::from_mut(argument)) };

    if code < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => TunError::PermissionDenied,
            _ => TunError::Io(err),
        });
    }
    Ok(())
}

/// Задаёт адрес, маску и MTU и поднимает интерфейс.
pub(super) fn configure(
    name: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> TunResult<()> {
    // Настройка интерфейса идёт через сокет, а не через сам адаптер: так
    // устроен интерфейс ядра, и никакого трафика через этот сокет не пойдёт.
    let control = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| TunError::adapter(name, err))?;

    ioctl(
        &control,
        request::SIOCSIFADDR,
        &mut IfReq::new(name)?.with_address(address),
    )?;
    ioctl(
        &control,
        request::SIOCSIFNETMASK,
        &mut IfReq::new(name)?.with_address(netmask),
    )?;
    ioctl(
        &control,
        request::SIOCSIFMTU,
        &mut IfReq::new(name)?.with_number(i32::from(mtu)),
    )?;

    // Флаги дописываются к уже стоящим, а не заменяют их: у адаптера есть
    // собственные (`IFF_POINTOPOINT`, `IFF_NOARP`), и стереть их значит
    // получить интерфейс, который система обслуживает не так.
    let mut flags = IfReq::new(name)?;
    ioctl(&control, request::SIOCGIFFLAGS, &mut flags)?;

    #[allow(
        clippy::cast_possible_truncation,
        reason = "флаги интерфейса помещаются в i16"
    )]
    let raised = flags.flags() | (libc::IFF_UP as i16) | (libc::IFF_RUNNING as i16);
    ioctl(
        &control,
        request::SIOCSIFFLAGS,
        &mut IfReq::new(name)?.with_flags(raised),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_survives_the_round_trip() {
        let request = IfReq::new("penguin0").expect("имя короткое");
        assert_eq!(request.name(), "penguin0");
    }

    #[test]
    fn an_overlong_name_is_refused() {
        // Молча обрезанное имя означает настройку чужого интерфейса.
        assert!(IfReq::new("этоименослишкомдлинное").is_err());
    }

    #[test]
    fn flags_survive_the_round_trip() {
        let request = IfReq::new("tun0").expect("имя").with_flags(0x1001);
        assert_eq!(request.flags(), 0x1001);
    }

    #[test]
    fn an_address_lands_where_the_kernel_reads_it() {
        // Раскладка `sockaddr_in`: семейство в первых двух байтах, адрес — с
        // четвёртого. Сдвиг здесь означает адаптер с чужим адресом.
        let request = IfReq::new("tun0")
            .expect("имя")
            .with_address(Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(request.data[4..8], [198, 18, 0, 1]);
    }
}
