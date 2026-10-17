//! Приложение iced: состояние, обновление, отрисовка, подписки.
//!
//! Размером окна владеет только [`uikit::window::Morph`]: окно без рамки меняет
//! размер командой мгновенно, `Morph` довозит его пружиной. `Resized` не
//! обрабатывается. Каждый контейнер от окна до содержимого объявляет размер
//! явно: растянутый ребёнок в группе «по содержимому» схлопывается в ноль.

pub mod message;
pub mod probe_queue;
pub mod state;
pub mod update;

use std::time::{Duration, Instant};

use iced::widget::{column, container, row};
use iced::{Element, Length, Point, Size, Subscription, Task, Theme, window};
use uikit::ThemeType;
use uikit::layout::gap;
use uikit::widgets::Tabs;
use uikit::window::{Anchor, Frame, Morph, WindowChrome, frame};

pub use self::message::{Message, Screen};
pub use self::state::State;
use crate::screens;

/// Имя программы: заголовок окна, шапка и подсказка значка в лотке.
pub const TITLE: &str = "Ostriacki Pingwin";

/// Размер содержимого в покое; окно больше на поле тени ([`frame::outer`]).
pub const COMPACT: Size = Size::new(360.0, 400.0);

/// Размер содержимого с раскрытой панелью.
pub const EXPANDED: Size = Size::new(800.0, 600.0);

/// Отступ от края окна до содержимого.
pub const PAGE_PADDING: f32 = 16.0;

/// Зазор между вкладками и под полосой вкладок.
pub const TAB_GAP: f32 = 6.0;

/// Шаг кадра, пока окно едет: 60 к/с.
const FRAME: Duration = Duration::from_millis(16);

/// Окно клиента.
pub struct App {
    state: State,
    chrome: WindowChrome,
    morph: Morph,
    theme: ThemeType,
    /// Настоящий идентификатор приходит с `Opened`; до него стоит временный.
    window: window::Id,
    /// `None` — лотка нет, окно сворачивается на панель задач.
    tray: Option<uikit::tray::Tray>,
    /// Окно спрятано в лоток (не то же, что свёрнуто).
    hidden: bool,
}

impl App {
    /// Создаёт окно и первую команду; `hidden` — открыться сразу в лотке.
    pub fn new(theme: ThemeType, hidden: bool) -> (Self, Task<Message>) {
        let mut state = State {
            palette: theme.to_iced_theme().palette(),
            ..State::default()
        };
        // Не обвинять службу до первого вопроса к ней.
        state.connection.starting = true;
        // Заставка печатается только при открытии окна, не в `default`.
        state.boot = state::Boot::begin();

        let app = Self {
            state,
            chrome: WindowChrome::new().framed(),
            morph: Morph::new(frame::outer(COMPACT))
                .with_anchor(Anchor::Center)
                .with_bounds(frame::outer(COMPACT), frame::outer(EXPANDED)),
            theme,
            window: window::Id::unique(),
            tray: None,
            hidden,
        };

        (app, update::bootstrap())
    }

    /// Заголовок окна.
    pub fn title(&self) -> String {
        TITLE.to_owned()
    }

    /// Разбирает сообщение.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        update::handle(self, message)
    }

    /// Собирает окно.
    pub fn view(&self) -> Element<'_, Message> {
        let header = uikit::window::header(self.window, TITLE)
            .on_close(Message::Window(message::WindowMessage::Close))
            .on_minimize(Message::Window(message::WindowMessage::Minimize))
            .without_maximize()
            .rounded(frame::RADIUS)
            .extra(
                row![
                    uikit::window::dot_button(Message::PanelToggled),
                    uikit::window::theme_switch(Message::ThemeToggle),
                ]
                .spacing(gap::SM),
            )
            .build();

        let body = container(if self.state.expanded {
            self.expanded()
        } else {
            self.compact()
        })
        .width(Length::Fill)
        .height(Length::Fill);

        let root = column![header, body]
            .width(Length::Fill)
            .height(Length::Fill);

        Frame::new(root).into()
    }

    /// Тема окна.
    pub fn theme(&self) -> Theme {
        self.theme.to_iced_theme()
    }

    /// Подписки окна.
    pub fn subscription(&self) -> Subscription<Message> {
        let mut streams = vec![
            iced::event::listen_with(|event, status, window_id| match event {
                iced::Event::Mouse(iced::mouse::Event::CursorMoved { position }) => Some(
                    Message::Window(message::WindowMessage::CursorMoved(position)),
                ),
                // Нажатие, взятое виджетом, окну не достаётся.
                iced::Event::Mouse(iced::mouse::Event::ButtonPressed(
                    iced::mouse::Button::Left,
                )) if status == iced::event::Status::Ignored => {
                    Some(Message::Window(message::WindowMessage::DragStarted))
                }
                iced::Event::Mouse(iced::mouse::Event::ButtonReleased(
                    iced::mouse::Button::Left,
                )) => Some(Message::Window(message::WindowMessage::DragStopped)),
                iced::Event::Window(iced::window::Event::Opened { position, size }) => Some(
                    Message::Window(message::WindowMessage::Opened(window_id, position, size)),
                ),
                iced::Event::Window(iced::window::Event::Moved(point)) => Some(Message::Window(
                    message::WindowMessage::Moved(point.x as i32, point.y as i32),
                )),
                _ => None,
            }),
            uikit::tray::events().map(|event| {
                Message::Window(match event {
                    uikit::tray::Event::Item(id) if id == crate::tray::QUIT => {
                        message::WindowMessage::Close
                    }
                    uikit::tray::Event::Item(_) => message::WindowMessage::Show,
                    uikit::tray::Event::Activated => message::WindowMessage::Toggle,
                })
            }),
        ];

        // Пока окно возится со службой, опрашивать её нельзя: каждый отказ
        // показывается как «Служба не отвечает» поверх запроса пароля.
        if !self.state.connection.is_busy_with_service() {
            streams.push(crate::ipc::subscription::events());
        }

        // Таймер кадров — только пока что-то движется.
        if !self.morph.settled() || self.state.boot.typing() {
            streams.push(iced::time::every(FRAME).map(Message::Frame));
        }

        Subscription::batch(streams)
    }

    /// Идентификатор главного окна.
    pub fn window(&self) -> window::Id {
        self.window
    }

    /// Запоминает открытое окно и заводит значок: до цикла событий его не бывает.
    ///
    /// Без значка окно, открытое спрятанным, приходится показать.
    pub fn window_opened(
        &mut self,
        id: window::Id,
        position: Option<Point>,
        size: Size,
    ) -> Task<Message> {
        self.window = id;
        self.morph.on_opened(position, size);
        self.tray = crate::tray::create();

        if self.hidden && self.tray.is_none() {
            return self.show();
        }
        Task::none()
    }

    /// Прячет окно в лоток или сворачивает, если лотка нет.
    pub fn hide(&mut self) -> Task<Message> {
        if self.tray.is_none() {
            return window::minimize(self.window, true);
        }

        self.hidden = true;
        window::set_mode(self.window, window::Mode::Hidden)
    }

    /// Достаёт окно из лотка.
    pub fn show(&mut self) -> Task<Message> {
        self.hidden = false;
        Task::batch([
            window::set_mode(self.window, window::Mode::Windowed),
            window::gain_focus(self.window),
        ])
    }

    /// Щелчок по значку: спрятать или показать.
    pub fn toggle_visibility(&mut self) -> Task<Message> {
        if self.hidden {
            self.show()
        } else {
            self.hide()
        }
    }

    /// Состояние окна.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Изменяемое состояние.
    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    /// Рамка окна.
    pub fn chrome_mut(&mut self) -> &mut WindowChrome {
        &mut self.chrome
    }

    /// Размер окна.
    pub fn morph_mut(&mut self) -> &mut Morph {
        &mut self.morph
    }

    /// Кадр движения окна.
    pub fn tick(&mut self, now: Instant) -> Task<Message> {
        self.morph.tick(self.window, now)
    }

    /// Раскрывает или сворачивает панель.
    pub fn toggle_panel(&mut self) {
        self.state.expanded = !self.state.expanded;
        self.morph.aim(frame::outer(if self.state.expanded {
            EXPANDED
        } else {
            COMPACT
        }));
    }

    /// Переключает тему; палитра в состоянии обновляется здесь же.
    pub fn next_theme(&mut self) -> ThemeType {
        self.theme = self.theme.next();
        self.state.palette = self.theme.to_iced_theme().palette();
        self.theme
    }

    fn compact(&self) -> Element<'_, Message> {
        container(screens::compact::view(&self.state))
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(PAGE_PADDING)
            .into()
    }

    fn expanded(&self) -> Element<'_, Message> {
        let tabs = container(
            Tabs::new(crate::i18n::s().screens, self.state.screen.index())
                .spacing(TAB_GAP)
                .on_select(|index| Message::Screen(Screen::from_index(index)))
                .build(),
        )
        .padding(iced::Padding {
            top: gap::MD,
            right: PAGE_PADDING,
            bottom: TAB_GAP,
            left: PAGE_PADDING,
        })
        .width(Length::Fill);

        let page = container(screens::view(&self.state))
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(iced::Padding {
                top: 0.0,
                right: PAGE_PADDING,
                bottom: PAGE_PADDING,
                left: PAGE_PADDING,
            });

        column![tabs, page]
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_compact_window_is_a_square_within_reason() {
        const { assert!(COMPACT.width >= 300.0 && COMPACT.width <= 400.0) };
        const { assert!(COMPACT.height >= 300.0 && COMPACT.height <= 440.0) };
    }

    #[test]
    fn the_panel_is_bigger_in_both_directions() {
        const { assert!(EXPANDED.width > COMPACT.width) };
        const { assert!(EXPANDED.height > COMPACT.height) };
    }

    #[test]
    fn tab_labels_match_the_screens() {
        assert_eq!(crate::i18n::s().screens.len(), Screen::ALL.len());
    }
}
