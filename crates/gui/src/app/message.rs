//! Сообщения верхнего уровня. Каждый экран приносит своё вложенное.
//!
//! Плоское перечисление на всё приложение вырастает до сотни вариантов и
//! перестаёт читаться; `match` по нему становится файлом на тысячу строк.
//! Вложенность делит его по экранам, и каждый разбирается отдельно — см.
//! [`crate::app::update`].

use penguin_ipc::schema::{Event, Response};

use crate::forms::rule::Action as DraftAction;
use crate::forms::server::Field as ServerField;

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
    /// Кадр движения окна.
    ///
    /// Приходит из таймера, пока окно едет: размер меняется пружиной, а
    /// пружине нужен ход времени.
    Frame(std::time::Instant),

    /// Связь с демоном.
    Ipc(IpcMessage),

    /// Главный экран.
    Home(HomeMessage),
    /// Серверы.
    Servers(ServersMessage),
    /// Раздельное тоннелирование.
    SplitTunnel(SplitTunnelMessage),
    /// Настройки.
    Settings(SettingsMessage),
}

/// Экраны раскрытой панели.
///
/// Главного экрана здесь нет: он и есть окно в покое, и вкладкой не
/// открывается.
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
    /// Окно открыто.
    ///
    /// Несёт настоящий идентификатор окна (в `iced 0.14` он приходит только
    /// событием, константы `window::Id::MAIN` больше нет) и его исходное
    /// положение и размер для `Morph`.
    Opened(iced::window::Id, Option<iced::Point>, iced::Size),
    /// Начато перетаскивание за шапку.
    DragStarted,
    /// Курсор сдвинулся.
    CursorMoved(iced::Point),
    /// Свернуть.
    ///
    /// Именно свернуть, а не спрятать: окно уходит на панель задач, откуда
    /// его достают одним щелчком. Тоннель при этом не трогается — свёрнутое
    /// окно означает «не мешай», а не «выключи».
    Minimize,
    /// Закрыть программу целиком.
    ///
    /// Не только окно: тоннель держит служба, и окно, закрывшееся само по
    /// себе, оставило бы после себя работающий TUN-адаптер, маршруты и весь
    /// трафик через нас. Поэтому сначала службе уходит
    /// [`penguin_ipc::schema::Request::Shutdown`], и только потом закрывается
    /// окно ([`Self::Stopped`]).
    Close,
    /// Служба остановлена — окно можно закрывать.
    Stopped,
    /// Кнопка отпущена: перетаскивание кончилось.
    DragStopped,
    /// Окно передвинули.
    ///
    /// Нужно `Morph`: он держит на месте центр, а для этого обязан знать, где
    /// окно сейчас.
    Moved(i32, i32),
}

/// Связь с демоном.
#[derive(Debug, Clone)]
pub enum IpcMessage {
    /// Демон ответил.
    Response(Box<Response>),
    /// Пришло событие.
    Event(Box<Event>),
    /// Связь потеряна.
    ///
    /// Пустая причина означает обратное — подписка подключилась. Отдельного
    /// сообщения под это нет намеренно: состояние связи одно, и менять его
    /// двумя путями значит однажды разойтись.
    Disconnected(String),
}

/// Главный экран.
#[derive(Debug, Clone)]
pub enum HomeMessage {
    /// Нажата кнопка подключения.
    ToggleConnection,
    /// Служба доведена до рабочего состояния — или нет.
    ///
    /// Отдельным сообщением, потому что установка идёт в другом процессе и
    /// занимает секунды: окно всё это время обязано оставаться живым.
    ServiceReady(bool),
    /// Служба проверена при открытии окна и, если надо, поднята.
    ///
    /// Отличается от [`Self::ServiceReady`] тем, что идёт следом: там службу
    /// поднимали по нажатию «Подключить», и дальше надо подключаться. Здесь —
    /// просто чтобы окну было у кого спросить настройки и состояние.
    ServiceChecked(bool),
}

/// Серверы.
#[derive(Debug, Clone)]
pub enum ServersMessage {
    /// Выбран профиль.
    Select(String),
    /// Проверить задержку.
    Probe,

    /// Открыть редактор. `None` — новый профиль.
    EditorOpened(Option<String>),
    /// Закрыть редактор, ничего не сохранив.
    EditorClosed,
    /// Изменено поле редактора.
    EditorChanged(ServerField, String),
    /// Вставлена ссылка-приглашение.
    LinkChanged(String),
    /// Переключена проверка сертификата.
    EditorInsecureToggled(bool),
    /// Сохранить профиль из редактора.
    EditorSubmitted,
    /// Удалить профиль.
    Removed(String),
}

/// Раздельное тоннелирование.
#[derive(Debug, Clone)]
pub enum SplitTunnelMessage {
    /// Сменить режим.
    ModeSelected(String),
    /// Правило включено или выключено.
    RuleToggled(usize, bool),
    /// Правило удалено.
    RuleRemoved(usize),
    /// Изменён адрес для проверки.
    ProbeDestinationChanged(String),
    /// Изменено приложение для проверки.
    ProbeProcessChanged(String),
    /// Запущена проверка.
    ///
    /// Ответ приходит обычным [`IpcMessage::Response`]: у проверки правил нет
    /// своего пути обратно, и заводить его значило бы разбирать один ответ в
    /// двух местах.
    ProbeRequested,

    /// Изменён поиск по списку приложений.
    AppSearchChanged(String),
    /// Приложение отмечено или снято — полным путём.
    AppToggled(String, bool),
    /// Изменено имя нового правила.
    DraftNameChanged(String),
    /// Изменена строка адресов нового правила.
    DraftAddressesChanged(String),
    /// Выбрано действие нового правила.
    DraftActionSelected(DraftAction),
    /// Новое правило добавлено в список.
    RuleAdded,

    /// Сохранить правила.
    Save,
}

/// Настройки.
#[derive(Debug, Clone)]
pub enum SettingsMessage {
    /// Автозапуск.
    AutostartToggled(bool),
    /// Автоподключение.
    AutoconnectToggled(bool),
    /// Kill switch.
    KillSwitchToggled(bool),
    /// Локальная сеть мимо тоннеля.
    AllowLanToggled(bool),
    /// Сохранить.
    Save,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_index_round_trips() {
        // Вкладки кита работают номерами; расхождение номера и экрана
        // означало бы, что щелчок открывает не то.
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
        // За панелью приходят чаще всего затем, чтобы сменить сервер.
        assert_eq!(Screen::default(), Screen::Servers);
        assert_eq!(Screen::Servers.index(), 0);
    }
}
