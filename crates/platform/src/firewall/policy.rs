//! Действие брандмауэра по умолчанию для исходящего трафика.
//!
//! # Почему не запрещающее правило
//!
//! Первая версия kill switch ставила правило «запретить всё» рядом с
//! разрешениями и рассчитывала, что разрешение сильнее. Это не так, и проверено
//! опытом: с парой «запрет + разрешение» на один и тот же адрес соединение не
//! проходит. Брандмауэр Windows разбирает запреты **раньше** разрешений, и одно
//! правило `remoteip=any action=block` перекрывает всё — включая трафик самого
//! тоннеля, ради которого kill switch и включают.
//!
//! Снаружи это выглядело безобиднее некуда: тоннель поднимается, счётчики стоят
//! на нуле, в журнале ни одной ошибки.
//!
//! # Правильный рычаг
//!
//! Действие по умолчанию. Оно применяется **последним**, после всех правил:
//! разрешения работают, а всё, что под них не попало, запрещено. Ровно то, что
//! нужно.
//!
//! Цена — состояние системы, которое обязательно надо вернуть: запрет по
//! умолчанию переживает и выход из программы, и перезагрузку. Поэтому прежнее
//! значение запоминается и восстанавливается точно таким же, а на случай, если
//! программу убили и вернуть не успели, есть [`recover`].

#![allow(unsafe_code, reason = "брандмауэр Windows доступен только через COM")]

use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, NET_FW_ACTION, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_PROFILE_TYPE2,
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NetFwPolicy2,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
};

use crate::error::{PlatformError, PlatformResult};

/// Профили брандмауэра, которые надо закрыть.
///
/// Все три: какой из них сейчас действует, зависит от сети, к которой человек
/// подключён, а переключиться она может и посреди сеанса.
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
        let previous = unsafe { policy.get_DefaultOutboundAction(profile) }
            .map_err(|err| PlatformError::Firewall(format!("не читается действие: {err}")))?;

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
    // Оставленный запрет — машина без сети, причём и после перезагрузки.
    // Молчать об этом нельзя ни при каких условиях.
    Err(PlatformError::rollback(
        "запрет исходящего трафика",
        failures.join("; "),
    ))
}

/// Снимает запрет, оставшийся от убитой программы.
///
/// Вызывается перед тем, как ставить свои правила. Признаком служат сами
/// правила: их ставят до запрета и снимают после него, поэтому «наши правила
/// есть, а исходящий запрещён» означает ровно одно — программу убили посреди
/// сеанса.
///
/// Возвращается при этом «разрешено», а не то, что стояло раньше: чего именно
/// человек хотел, узнать уже неоткуда, а машина без сети — худший из исходов.
pub fn recover(our_rules_present: bool) -> PlatformResult<()> {
    if !our_rules_present {
        return Ok(());
    }

    let policy = open()?;
    let mut restored = false;

    for profile in PROFILES {
        let Ok(current) = (unsafe { policy.get_DefaultOutboundAction(profile) }) else {
            continue;
        };
        if current != NET_FW_ACTION_BLOCK {
            continue;
        }
        if unsafe { policy.put_DefaultOutboundAction(profile, NET_FW_ACTION_ALLOW) }.is_ok() {
            restored = true;
        }
    }

    if restored {
        tracing::warn!("снят запрет исходящего трафика, оставшийся от прошлого запуска");
    }
    Ok(())
}

/// Открывает управление брандмауэром.
fn open() -> PlatformResult<INetFwPolicy2> {
    // COM может быть уже поднят на этом потоке — тогда вызов вернёт отказ, и
    // это не ошибка: нам нужно, чтобы он работал, а не чтобы его подняли мы.
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };

    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
        .map_err(|err| PlatformError::Firewall(format!("брандмауэр недоступен: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_saved_means_nothing_to_restore() {
        // Лишний вызов на пустом наборе означал бы обращение к брандмауэру
        // там, где мы его не трогали.
        assert!(Saved::default().is_empty());
        assert!(restore(&Saved::default()).is_ok());
    }

    #[test]
    fn all_three_profiles_are_covered() {
        // Какой профиль действует, зависит от сети, а сеть может смениться
        // посреди сеанса: закрытый наполовину kill switch не закрыт вовсе.
        assert_eq!(PROFILES.len(), 3);
    }

    #[test]
    fn recovery_without_our_rules_touches_nothing() {
        // Запрет мог поставить не мы. Снимать чужой — значит ослаблять чужую
        // защиту без спроса.
        assert!(recover(false).is_ok());
    }
}
