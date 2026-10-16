//! Действие брандмауэра по умолчанию для исходящего трафика.
//!
//! Запрещающее правило рядом с разрешениями не годится: Windows разбирает запреты раньше
//! разрешений, и `block` перекрывает даже трафик самого тоннеля. Действие по умолчанию
//! применяется последним, но переживает выход и перезагрузку, поэтому прежнее значение
//! запоминается, а после убитой программы есть [`recover`].

#![allow(unsafe_code, reason = "брандмауэр Windows доступен только через COM")]

use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, NET_FW_ACTION, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE_TYPE2,
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NetFwPolicy2,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
};

use crate::error::{PlatformError, PlatformResult};

/// Все три профиля: действующий зависит от сети и может смениться посреди сеанса.
const PROFILES: [NET_FW_PROFILE_TYPE2; 3] = [
    NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC,
];

/// Прежние действия по умолчанию — то, что надо вернуть.
#[derive(Debug, Default, Clone)]
pub struct Saved {
    actions: Vec<(i32, i32)>,
}

impl Saved {
    /// Ничего не менялось.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Запрещает исходящий трафик по умолчанию и возвращает прежние значения.
pub fn block_outbound() -> PlatformResult<Saved> {
    let policy = open()?;
    let mut actions = Vec::with_capacity(PROFILES.len());

    for profile in PROFILES {
        // SAFETY: `policy` — живой COM-интерфейс.
        let previous = unsafe { policy.get_DefaultOutboundAction(profile) }
            .map_err(|err| PlatformError::Firewall(format!("не читается действие: {err}")))?;

        // SAFETY: то же.
        unsafe { policy.put_DefaultOutboundAction(profile, NET_FW_ACTION_BLOCK) }.map_err(
            |err| PlatformError::Firewall(format!("не удалось запретить исходящий трафик: {err}")),
        )?;

        actions.push((profile.0, previous.0));
    }

    tracing::debug!("исходящий трафик запрещён по умолчанию");
    Ok(Saved { actions })
}

/// Возвращает действия по умолчанию такими, какими они были.
pub fn restore(saved: &Saved) -> PlatformResult<()> {
    if saved.is_empty() {
        return Ok(());
    }

    let policy = open()?;
    let mut failures = Vec::new();

    for (profile, action) in &saved.actions {
        // SAFETY: `policy` — живой COM-интерфейс.
        let result = unsafe {
            policy.put_DefaultOutboundAction(NET_FW_PROFILE_TYPE2(*profile), NET_FW_ACTION(*action))
        };
        if let Err(err) = result {
            failures.push(err.to_string());
        }
    }

    if failures.is_empty() {
        return Ok(());
    }
    Err(PlatformError::rollback(
        "запрет исходящего трафика",
        failures.join("; "),
    ))
}

/// Снимает запрет, оставшийся от убитой программы, возвращая «разрешено»: прежнее значение
/// неизвестно. Признак — наши правила есть при запрещённом исходящем; чужой запрет не трогается.
pub fn recover(our_rules_present: bool) -> PlatformResult<()> {
    if !our_rules_present {
        return Ok(());
    }

    let policy = open()?;
    let mut restored = false;

    for profile in PROFILES {
        // SAFETY: `policy` — живой COM-интерфейс.
        let Ok(current) = (unsafe { policy.get_DefaultOutboundAction(profile) }) else {
            continue;
        };
        if current != NET_FW_ACTION_BLOCK {
            continue;
        }
        // SAFETY: то же.
        if unsafe { policy.put_DefaultOutboundAction(profile, NET_FW_ACTION_ALLOW) }.is_ok() {
            restored = true;
        }
    }

    if restored {
        tracing::warn!("снят запрет исходящего трафика, оставшийся от прошлого запуска");
    }
    Ok(())
}

/// Открывает управление брандмауэром; уже поднятый COM на потоке — не ошибка.
fn open() -> PlatformResult<INetFwPolicy2> {
    // SAFETY: инициализация COM без аргументов.
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };

    // SAFETY: класс и контекст заданы константами.
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
        .map_err(|err| PlatformError::Firewall(format!("брандмауэр недоступен: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_saved_means_nothing_to_restore() {
        assert!(Saved::default().is_empty());
        assert!(restore(&Saved::default()).is_ok());
    }

    #[test]
    fn all_three_profiles_are_covered() {
        assert_eq!(PROFILES.len(), 3);
    }

    #[test]
    fn recovery_without_our_rules_touches_nothing() {
        assert!(recover(false).is_ok());
    }
}
