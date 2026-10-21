//! Повтор начального подключения, пока система поднимает сеть.

use std::future::Future;

use penguin_core::id::ProfileId;
use penguin_proto::error::ProtocolError;

use crate::state::StateMachine;
use crate::supervisor::{self, Decision};

pub(crate) async fn connect<T, F, Fut>(
    mut connect: F,
    state: &StateMachine,
    profile: &ProfileId,
) -> Result<T, ProtocolError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ProtocolError>>,
{
    let mut attempt = 0;
    loop {
        let error = match connect().await {
            Ok(outbound) => return Ok(outbound),
            Err(error) => error,
        };
        let Decision::Retry {
            delay,
            attempt: next,
        } = supervisor::decide(&error, attempt)
        else {
            return Err(error);
        };
        attempt = next;
        state.reconnecting(profile.clone(), attempt, error.to_string());
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use penguin_core::state::TunnelState;

    use super::*;
    use crate::events::EventBus;

    #[tokio::test(start_paused = true)]
    async fn waits_for_network_then_connects() {
        let state = StateMachine::new(EventBus::new());
        let mut attempts = 0;
        let began = tokio::time::Instant::now();
        let result = connect(
            || {
                attempts += 1;
                std::future::ready(if attempts < 3 {
                    Err(ProtocolError::Connect("сеть не готова".to_owned()))
                } else {
                    Ok(())
                })
            },
            &state,
            &ProfileId::new("home"),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(attempts, 3);
        assert_eq!(began.elapsed(), Duration::from_secs(3));
        assert!(matches!(
            state.current(),
            TunnelState::Reconnecting { attempt: 2, .. }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_errors_are_not_retried() {
        let state = StateMachine::new(EventBus::new());
        let mut attempts = 0;
        let result: Result<(), _> = connect(
            || {
                attempts += 1;
                std::future::ready(Err(ProtocolError::AuthRejected))
            },
            &state,
            &ProfileId::new("home"),
        )
        .await;
        assert!(matches!(result, Err(ProtocolError::AuthRejected)));
        assert_eq!(attempts, 1);
    }
}
