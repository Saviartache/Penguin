//! Kill switch: пока тоннель не работает, наружу не идёт ничего.
//!
//! Исключения из запрета: петля, локальная сеть (по запросу) и адрес сервера.
//!
//! ```text
//!   тоннель работает ──► разрешено: тоннель, петля, (локальная сеть)
//!   тоннель упал     ──► разрешено: петля, (локальная сеть)
//!   клиент вышел     ──► правила сняты, всё как было
//! ```

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
    /// Подсеть тоннеля, например `198.18.0.0/15`: трафик тоннеля опознаётся по адресу источника
    /// (имя интерфейса меняется вместе с языком системы). `None` перекроет и сам тоннель.
    pub tunnel_subnet: Option<String>,
    /// Разрешить локальную сеть.
    pub allow_lan: bool,
    /// Адреса, до которых пускать всегда, — прежде всего сам сервер.
    pub allow_addresses: Vec<IpAddr>,
}

/// Снимает запрет, оставшийся от прошлого запуска; зовётся при старте службы, потому что запрет
/// переживает перезагрузку, а интернета для починки уже нет.
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

/// Подсети локальной сети для `allow_lan` (общие для Linux и macOS; Windows — см. `policy`).
#[cfg(not(windows))]
pub(crate) fn lan_networks() -> &'static [&'static str] {
    &[
        // Частные сети (RFC 1918).
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        // Без DHCP (RFC 3927).
        "169.254.0.0/16",
        // Многоадресная рассылка: поиск принтеров и колонок.
        "224.0.0.0/4",
        "fe80::/10",
        "ff00::/8",
    ]
}

/// Kill switch с гарантированным снятием: и по обычному выходу, и по [`Drop`].
#[derive(Debug, Default)]
pub struct KillSwitch {
    engaged: bool,
    /// Прежнее действие брандмауэра по умолчанию: оно переживает выход и перезагрузку,
    /// восстановить его больше неоткуда.
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
        // Признак снимается до попытки: иначе неудача зациклит `Drop`.
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
        let mut switch = KillSwitch::new();
        switch.disengage().expect("снимать нечего");
    }

    #[test]
    fn rules_carry_the_server_address() {
        let rules = FirewallRules {
            tunnel_subnet: Some("198.18.0.0/15".to_owned()),
            allow_lan: true,
            allow_addresses: vec!["203.0.113.5".parse().expect("адрес")],
        };
        assert_eq!(rules.allow_addresses.len(), 1);
        assert!(rules.allow_lan);
    }
}
