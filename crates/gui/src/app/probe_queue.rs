//! Очередь проверки задержки: серверы по одному, результат виден сразу.

use std::collections::VecDeque;

/// Очередь профилей на проверку; чистая логика, без iced и сети.
#[derive(Debug, Default)]
pub struct ProbeQueue {
    current: Option<String>,
    pending: VecDeque<String>,
}

impl ProbeQueue {
    /// Начинает прогон; идущий отбрасывается.
    pub fn start(&mut self, ids: impl IntoIterator<Item = String>) {
        self.pending = ids.into_iter().collect();
        self.current = self.pending.pop_front();
    }

    /// Профиль, ответа по которому ждём.
    pub fn current(&self) -> Option<&str> {
        self.current.as_deref()
    }

    /// Идёт ли прогон.
    pub fn is_running(&self) -> bool {
        self.current.is_some()
    }

    /// Учитывает ответ; `true` — он по текущему профилю и очередь сдвинулась.
    /// Чужие и запоздалые ответы очередь не трогают.
    pub fn answered(&mut self, id: &str) -> bool {
        if self.current.as_deref() != Some(id) {
            return false;
        }
        self.current = self.pending.pop_front();
        true
    }

    /// Прекращает прогон.
    pub fn cancel(&mut self) {
        self.current = None;
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn profiles_go_one_by_one_in_order() {
        let mut queue = ProbeQueue::default();
        queue.start(ids(&["a", "b"]));
        assert_eq!(queue.current(), Some("a"));

        assert!(queue.answered("a"));
        assert_eq!(queue.current(), Some("b"));

        assert!(queue.answered("b"));
        assert!(!queue.is_running());
    }

    #[test]
    fn a_stray_answer_does_not_move_the_queue() {
        let mut queue = ProbeQueue::default();
        queue.start(ids(&["a", "b"]));

        assert!(!queue.answered("b"));
        assert_eq!(queue.current(), Some("a"));
    }

    #[test]
    fn a_new_run_drops_the_old_one() {
        let mut queue = ProbeQueue::default();
        queue.start(ids(&["a", "b"]));
        queue.start(ids(&["c"]));

        assert!(!queue.answered("a"));
        assert!(queue.answered("c"));
        assert!(!queue.is_running());
    }

    #[test]
    fn an_empty_run_is_not_running() {
        let mut queue = ProbeQueue::default();
        queue.start(Vec::new());
        assert!(!queue.is_running());
    }

    #[test]
    fn cancel_stops_everything() {
        let mut queue = ProbeQueue::default();
        queue.start(ids(&["a", "b"]));
        queue.cancel();
        assert!(!queue.is_running());
        assert!(!queue.answered("a"));
    }
}
