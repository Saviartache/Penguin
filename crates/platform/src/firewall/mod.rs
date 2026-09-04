//! Kill switch: при разрыве тоннеля трафик не должен пойти напрямую.
//!
//! Без него разрыв соединения означает, что весь трафик молча уходит мимо
//! тоннеля — и пользователь узнаёт об этом в лучшем случае из значка в трее.
//! Хуже того, происходит это именно тогда, когда защита нужнее всего: когда
//! соединение рвут намеренно.
//!
//! Поэтому правило простое: пока тоннель не работает, наружу не идёт ничего.
//!
//! ```text
//!   тоннель работает ──► разрешено: тоннель, петля, (локальная сеть)
//!   тоннель упал     ──► разрешено: петля, (локальная сеть)
//!   клиент вышел     ──► правила сняты, всё как было
//! ```
//!
//! Три исключения из запрета неизбежны. **Петля** — иначе перестанут работать
//! и сам клиент, и половина приложений. **Локальная сеть** — иначе исчезнут
//! принтер и сетевые диски, и первое, что сделает пользователь, — выключит
//! клиент целиком. **Адрес сервера** — иначе тоннель, ради которого всё
//! затевалось, не поднимется.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod policy;
#[cfg(windows)]
pub mod windows;

use std::net::IpAddr;

use crate::error::PlatformResult;

/// Что разрешить, пока всё остальное запрещено.
#[derive(Debug, Clone, Default)]
pub struct FirewallRules {
    /// Подсеть тоннеля, например `198.18.0.0/15`.
    ///
    /// По ней трафик тоннеля и опознаётся: пакет, ушедший в адаптер, получает
    /// адрес источника отсюда. Не по номеру интерфейса — `netsh` принимает
    /// интерфейс по имени, а имя меняется вместе с языком системы.
    ///
    /// `None` означает kill switch, который перекроет и сам тоннель.
    pub tunnel_subnet: Option<String>,
    /// Разрешить локальную сеть.
    pub allow_lan: bool,
    /// Адреса, до которых пускать всегда, — прежде всего сам сервер.
    pub allow_addresses: Vec<IpAddr>,
}

/// Снимает запрет, оставшийся от прошлого запуска.
///
/// Вызывается при старте службы, а не только перед подключением. Разница
/// решающая: убитая программа оставляет запрет исходящего трафика, а он
/// переживает перезагрузку. Служба поднимается вместе с системой — значит,
/// после перезагрузки сеть вернётся сама, без единого действия человека,
/// который к тому же не смог бы ничего найти: интернета у него нет.
pub fn recover_leftovers() -> PlatformResult<()> {
    #[cfg(windows)]
    {
        windows::recover_leftovers()
    }
    #[cfg(target_os = "linux")]
    {
        linux::disengage()
    }
    #[cfg(target_os = "macos")]
    {
        macos::recover_leftovers()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Ok(())
    }
}

/// Подсети локальной сети, которые открывает `allow_lan`.
///
/// Без них исчезнут принтер и сетевые диски, и первое, что сделает
/// пользователь, — выключит клиент целиком. Список общий для Linux и macOS:
/// адреса эти заданы стандартом, а не операционной системой. Windows задаёт
/// то же самое своими средствами — см. `policy`.
#[cfg(not(windows))]
pub(crate) fn lan_networks() -> &'static [&'static str] {
    &[
        // Частные сети (RFC 1918).
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        // Адреса, назначаемые без DHCP (RFC 3927), — там же живёт и часть
        // обнаружения устройств в сети.
        "169.254.0.0/16",
        // Многоадресная рассылка: ею работает поиск принтеров и колонок.
        "224.0.0.0/4",
        // То же самое для IPv6: локальные адреса связи и рассылка.
        "fe80::/10",
        "ff00::/8",
    ]
}

/// Kill switch с гарантированным снятием.
///
/// Правила снимаются и по обычному выходу, и по [`Drop`]. Оставленное правило
/// означает машину без сети, а пользователь не свяжет это с VPN-клиентом,
/// который он уже закрыл.
#[derive(Debug, Default)]
pub struct KillSwitch {
    engaged: bool,
    /// Что вернуть системе при снятии.
    ///
    /// Запрет живёт в действии брандмауэра по умолчанию, а оно переживает и
    /// выход из программы, и перезагрузку. Прежнее значение обязано дожить до
    /// снятия здесь: восстановить его больше неоткуда.
    #[cfg(windows)]
    saved: windows::Saved,
}

impl KillSwitch {
    /// Выключенный kill switch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Включает запрет.
    pub fn engage(&mut self, rules: &FirewallRules) -> PlatformResult<()> {
        #[cfg(windows)]
        {
            self.saved = windows::engage(rules)?;
        }
        #[cfg(not(windows))]
        {
            engage_rules(rules)?;
        }
        self.engaged = true;
        Ok(())
    }

    /// Снимает запрет.
    pub fn disengage(&mut self) -> PlatformResult<()> {
        if !self.engaged {
            return Ok(());
        }
        // Признак снимается до попытки: неудачное снятие лучше повторить
        // руками, чем зациклиться на нём в `Drop`.
        self.engaged = false;

        #[cfg(windows)]
        {
            let saved = std::mem::take(&mut self.saved);
            windows::disengage(&saved)
        }
        #[cfg(not(windows))]
        {
            disengage_rules()
        }
    }

    /// Запрет действует.
    pub fn is_engaged(&self) -> bool {
        self.engaged
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        if self.engaged
            && let Err(err) = self.disengage()
        {
            tracing::error!(%err, "правила брандмауэра остались в системе");
        }
    }
}

#[cfg(not(windows))]
fn engage_rules(rules: &FirewallRules) -> PlatformResult<()> {
    #[cfg(target_os = "linux")]
    {
        linux::engage(rules)
    }
    #[cfg(target_os = "macos")]
    {
        macos::engage(rules)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = rules;
        Err(crate::error::PlatformError::Unsupported("kill switch"))
    }
}

#[cfg(not(windows))]
fn disengage_rules() -> PlatformResult<()> {
    #[cfg(target_os = "linux")]
    {
        linux::disengage()
    }
    #[cfg(target_os = "macos")]
    {
        macos::disengage()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(crate::error::PlatformError::Unsupported("kill switch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_disengaged() {
        let switch = KillSwitch::new();
        assert!(!switch.is_engaged());
    }

    #[test]
    fn disengaging_an_inactive_switch_is_a_no_op() {
        // Снятие вызывается на каждом пути выхода; отсутствие правил — не
        // ошибка.
        let mut switch = KillSwitch::new();
        switch.disengage().expect("снимать нечего");
    }

    #[test]
    fn rules_carry_the_server_address() {
        // Без него тоннель, ради которого kill switch и включён, не
        // поднимется.
        let rules = FirewallRules {
            tunnel_subnet: Some("198.18.0.0/15".to_owned()),
            allow_lan: true,
            allow_addresses: vec!["203.0.113.5".parse().expect("адрес")],
        };
        assert_eq!(rules.allow_addresses.len(), 1);
        assert!(rules.allow_lan);
    }
}
