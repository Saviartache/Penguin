//! Окно развёртывания: поля, ход работы и причина прошлой неудачи.

use super::form::Form;
use super::progress::{self, Event, Progress};

/// Состояние окна развёртывания.
#[derive(Debug, Default)]
pub struct Deploy {
    /// Набранное; при неудаче остаётся для повтора.
    pub form: Form,
    /// Ход работы; `None` — не идёт.
    pub progress: Option<Progress>,
    /// Почему прошлая попытка не вышла.
    pub error: Option<String>,
}

impl Deploy {
    /// Идёт ли развёртывание.
    pub fn running(&self) -> bool {
        self.progress.is_some()
    }

    /// Начинает: запрос для CLI либо причина, по которой нельзя (ничего не меняется).
    pub fn start(&mut self, profile: &str) -> Result<String, String> {
        let request = self.form.request(profile)?;
        self.progress = Some(Progress::default());
        self.error = None;
        Ok(request)
    }

    /// Принимает строку вывода.
    pub fn apply(&mut self, event: Event) {
        if let Some(progress) = self.progress.as_mut() {
            progress.apply(event);
        }
    }

    /// Процесс завершился: ссылка при успехе, иначе причина в [`Self::error`].
    pub fn finish(&mut self, result: Result<(), String>) -> Option<String> {
        let progress = self.progress.take()?;
        // Этап, на котором сорвалось, — первое, что спросят.
        let stage = progress.current().map(|id| progress::title(id).to_owned());
        let reason = match (result, progress.link) {
            (Ok(()), Some(link)) => return Some(link),
            (Ok(()), None) => crate::i18n::s().deploy_no_link.to_owned(),
            (Err(reason), _) => reason,
        };
        self.error = Some(match stage {
            Some(stage) => format!("{stage}: {reason}"),
            None => reason,
        });
        None
    }

    /// Отмена идущего развёртывания: поля снова правятся.
    pub fn cancel(&mut self) {
        self.progress = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::deploy::Field;

    fn ready() -> Deploy {
        let mut deploy = Deploy::default();
        deploy.form.set(Field::Host, "203.0.113.5".to_owned());
        deploy.form.set(Field::Domain, "vpn.example.com".to_owned());
        deploy
    }

    #[test]
    fn an_invalid_form_does_not_start() {
        let mut deploy = Deploy::default();
        assert!(deploy.start("").is_err());
        assert!(!deploy.running());
    }

    #[test]
    fn success_returns_the_link() {
        let mut deploy = ready();
        deploy.error = Some("прошлая".to_owned());
        deploy.start("").expect("начинается");
        assert!(deploy.running() && deploy.error.is_none());

        deploy.apply(Event::Link("pingwin://x".to_owned()));
        assert_eq!(deploy.finish(Ok(())), Some("pingwin://x".to_owned()));
        assert!(!deploy.running());
    }

    #[test]
    fn failure_names_the_stage_and_keeps_the_fields() {
        let mut deploy = ready();
        deploy.start("").expect("начинается");
        deploy.apply(Event::Step("cert".to_owned()));
        assert_eq!(deploy.finish(Err("DNS не указывает".to_owned())), None);

        let error = deploy.error.clone().expect("причина");
        assert!(error.starts_with(crate::i18n::s().stage_cert), "{error}");
        assert!(error.ends_with("DNS не указывает"));
        assert_eq!(deploy.form.get(Field::Host), "203.0.113.5");
    }

    #[test]
    fn success_without_a_link_is_a_failure() {
        let mut deploy = ready();
        deploy.start("").expect("начинается");
        assert_eq!(deploy.finish(Ok(())), None);
        assert_eq!(
            deploy.error.as_deref(),
            Some(crate::i18n::s().deploy_no_link)
        );
    }
}
