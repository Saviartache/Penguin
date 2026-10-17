//! Сообщения верхнего уровня; каждый экран приносит своё вложенное.

use penguin_config::import::Imported;
use penguin_config::schema::routing::TunnelMode;
use penguin_ipc::schema::{Event, Response};

use crate::forms::rule::{Action as DraftAction, Section as DraftSection};

/// Что произошло в интерфейсе.
#[derive(Debug, Clone)]
pub enum Message {
    /// Окно: перетаскивание, размер, закрытие.
    Window(WindowMessage),
    /// Переключение экрана.
    Screen(Screen),
    /// Смена темы.
    ThemeToggle,
    /// Раскрыть или свернуть панель настроек.
    PanelToggled,
    /// Кадр таймера, пока окно едет.
    Frame(std::time::Instant),
    /// Связь с демоном.
    Ipc(IpcMessage),
    /// Главный экран.
    Home(HomeMessage),
    /// Серверы.
    Servers(ServersMessage),
    /// Раздельное тоннелирование.
    SplitTunnel(SplitTunnelMessage),
    /// Журнал.
    Logs(LogsMessage),
    /// Настройки.
    Settings(SettingsMessage),
    /// Обновление программы.
    Update(UpdateMessage),
}

/// Обновление программы; сеть ходит в отдельном процессе (`penguin update`).
#[derive(Debug, Clone)]
pub enum UpdateMessage {
    /// Кнопка «Проверить».
    Check,
    /// Проверка закончилась; `manual` — по кнопке, а не при запуске.
    Checked {
        /// Нажал человек.
        manual: bool,
        /// Ответ или причина отказа.
        result: Result<penguin_update::CheckReport, String>,
    },
    /// Кнопка «Обновить».
    Install,
    /// Установка закончилась: путь файла, который надо запустить заново.
    Installed(Result<std::path::PathBuf, String>),
}

/// Журнал: копирование строки и правило по соединению.
#[derive(Debug, Clone)]
pub enum LogsMessage {
    /// Нажата запись: номер и кнопка мыши.
    LinePressed(usize, iced::mouse::Button),
    /// Плашка «скопировано» отстояла своё; номер — чьё ожидание кончилось.
    CopiedShown(u64),
    /// Ловить адрес.
    CatchHost(bool),
    /// Ширина адреса — номер варианта.
    WidthSelected(usize),
    /// Ловить приложение.
    CatchApp(bool),
    /// Действие новой группы.
    ActionSelected(DraftAction),
    /// Куда вписать: группа или `None` — новая.
    TargetSelected(Option<usize>),
    /// Добавить и сохранить.
    RuleSaved,
    /// Закрыть окно.
    RuleClosed,
}

/// Экраны раскрытой панели; главный экран — окно в покое, не вкладка.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    /// Список серверов.
    #[default]
    Servers,
    /// Правила раздельного тоннелирования.
    SplitTunnel,
    /// Журнал.
    Logs,
    /// Настройки.
    Settings,
}

impl Screen {
    /// Все экраны в порядке вкладок.
    pub const ALL: [Self; 4] = [Self::Servers, Self::SplitTunnel, Self::Logs, Self::Settings];

    /// Номер вкладки.
    pub fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|screen| *screen == self)
            .unwrap_or(0)
    }

    /// Экран по номеру вкладки.
    pub fn from_index(index: usize) -> Self {
        Self::ALL.get(index).copied().unwrap_or_default()
    }
}

/// Управление окном.
#[derive(Debug, Clone, Copy)]
pub enum WindowMessage {
    /// Окно открыто: настоящий идентификатор (в `iced 0.14` приходит только
    /// событием), положение и размер для `Morph`.
    Opened(iced::window::Id, Option<iced::Point>, iced::Size),
    /// Начато перетаскивание за шапку.
    DragStarted,
    /// Курсор сдвинулся.
    CursorMoved(iced::Point),
    /// Свернуть в лоток, без лотка — на панель задач; тоннель не трогается.
    Minimize,
    /// Достать окно из лотка.
    Show,
    /// Щелчок по значку: спрятать или показать.
    Toggle,
    /// Закрыть программу: сначала службе уходит `Request::Shutdown`, иначе
    /// остались бы TUN и маршруты; потом [`Self::Stopped`].
    Close,
    /// Служба остановлена — окно можно закрывать.
    Stopped,
    /// Кнопка отпущена.
    DragStopped,
    /// Окно передвинули; `Morph` держит центр и должен знать положение.
    Moved(i32, i32),
}

/// Связь с демоном.
#[derive(Debug, Clone)]
pub enum IpcMessage {
    /// Демон ответил.
    Response(Box<Response>),
    /// Пришло событие.
    Event(Box<Event>),
    /// Связь потеряна; пустая причина означает, что подписка подключилась.
    Disconnected(String),
}

/// Главный экран.
#[derive(Debug, Clone)]
pub enum HomeMessage {
    /// Нажата кнопка подключения.
    ToggleConnection,
    /// Служба проверена или поднята (при открытии окна или кнопкой «Запустить службу»).
    ServiceChecked(ServiceOutcome),
}

/// Итог попытки поднять службу; отказ в окне прав — решение человека, не сбой.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceOutcome {
    /// Служба работает и отвечает.
    Ready,
    /// Человек отказался дать права.
    Refused,
    /// Не получилось, и вот почему.
    Failed(String),
}

/// Серверы.
#[derive(Debug, Clone)]
pub enum ServersMessage {
    /// Изменён поиск по списку.
    SearchChanged(String),
    /// Выбран профиль.
    Select(String),
    /// Проверить задержку.
    Probe,
    /// Показать список протоколов: поля формы приносит протокол.
    PickerOpened,
    /// Закрыть список протоколов.
    PickerClosed,
    /// Выбран протокол по имени: номер в каталоге нестабилен.
    ProtocolChosen(&'static str),
    /// Открыть редактор существующего профиля.
    EditorOpened(String),
    /// Закрыть редактор, ничего не сохранив.
    EditorClosed,
    /// Изменено имя профиля.
    EditorNameChanged(String),
    /// Изменено поле формы — по месту в форме, не по имени.
    EditorChanged(usize, String),
    /// Переключён флажок формы.
    EditorToggled(usize, bool),
    /// Вставлена ссылка-приглашение.
    LinkChanged(String),
    /// Сохранить профиль из редактора.
    EditorSubmitted,
    /// Удалить профиль.
    Removed(String),
}

/// Раздельное тоннелирование.
#[derive(Debug, Clone)]
pub enum SplitTunnelMessage {
    /// Выбрано, куда идёт всё остальное.
    ModeSelected(TunnelMode),
    /// Изменён поиск по списку правил.
    SearchChanged(String),
    /// Правило включено или выключено.
    RuleToggled(usize, bool),
    /// Правило переставлено: откуда, куда.
    RuleMoved(usize, usize),
    /// Правило удалено.
    RuleRemoved(usize),
    /// Открыть окно проверки.
    ProbeOpened,
    /// Закрыть окно проверки.
    ProbeClosed,
    /// Изменён адрес для проверки.
    ProbeDestinationChanged(String),
    /// Изменено приложение для проверки.
    ProbeProcessChanged(String),
    /// Запущена проверка; ответ приходит как [`IpcMessage::Response`].
    ProbeRequested,
    /// Открыть окно группы: новой или правила с этим номером.
    EditorOpened(Option<usize>),
    /// Закрыть окно, ничего не добавив.
    EditorClosed,
    /// Изменён поиск по списку приложений.
    AppSearchChanged(String),
    /// Приложение отмечено или снято — полным путём.
    AppToggled(String, bool),
    /// Показать системное окно выбора файла (список службы — только запущенное).
    AppPickRequested,
    /// Ответ окна выбора; `Ok(None)` — закрыто без выбора, не ошибка.
    AppPicked(Result<Option<String>, String>),
    /// Изменено имя нового правила.
    DraftNameChanged(String),
    /// Открыт раздел группы.
    DraftSectionSelected(DraftSection),
    /// Изменено поле адресов и портов: и поиск по списку, и новое значение.
    DraftEntryChanged(String),
    /// Enter или «Добавить»: понятое из поля уходит в разделы.
    DraftEntrySubmitted,
    /// Убрать адрес или порт.
    DraftValueRemoved(String),
    /// Выбрано действие группы.
    DraftActionSelected(DraftAction),
    /// Группа добавлена в список или заменила прежнюю.
    DraftSaved,
    /// Показать окно выбора списка правил.
    ImportRequested,
    /// Разобранный список; `Ok(None)` — окно закрыто без выбора.
    Imported(Result<Option<Imported>, String>),
    /// Показать окно сохранения списка правил.
    ExportRequested,
    /// Итог выгрузки строкой для человека; `Ok(None)` — окно закрыто без выбора.
    Exported(Result<Option<String>, String>),
    /// Сохранить правила.
    Save,
}

/// Настройки; каждый переключатель уезжает демону сразу, без «Сохранить».
#[derive(Debug, Clone)]
pub enum SettingsMessage {
    /// Автозапуск.
    Autostart(bool),
    /// Автоподключение.
    Autoconnect(bool),
    /// Kill switch.
    KillSwitch(bool),
    /// Локальная сеть мимо тоннеля.
    AllowLan(bool),
    /// Забирать маршрут по умолчанию.
    CaptureDefaultRoute(bool),
    /// Перехват запросов имён.
    DnsHijack(bool),
    /// Подробность журнала службы.
    VerboseLog(bool),
    /// Проверять обновления при запуске.
    CheckUpdates(bool),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_index_round_trips() {
        for screen in Screen::ALL {
            assert_eq!(Screen::from_index(screen.index()), screen);
        }
    }

    #[test]
    fn unknown_index_falls_back_to_the_first_tab() {
        assert_eq!(Screen::from_index(999), Screen::Servers);
    }

    #[test]
    fn servers_open_first() {
        assert_eq!(Screen::default(), Screen::Servers);
        assert_eq!(Screen::Servers.index(), 0);
    }
}
