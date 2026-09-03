//! Приложение iced: состояние, обновление, отрисовка, подписки.
//!
//! # Окно двух размеров
//!
//! В покое клиент — квадрат с ладонь: панель и кнопка. Всё остальное —
//! серверы, правила, журнал, настройки — за кнопкой в шапке, и окно
//! раскрывается под них само. Свернувшись обратно, оно возвращает прежний
//! размер.
//!
//! Размером владеет [`uikit::window::Morph`] и **только** он. Окно без
//! системной рамки меняет размер лишь командой, а команда мгновенна: прыжок из
//! квадрата в панель читается как сбой отрисовки. `Morph` довозит размер
//! пружиной, кадр за кадром, и держит центр на месте — иначе окно на глазах
//! сползало бы вправо-вниз.
//!
//! Отсюда два следствия, оба из документации кита. Первое: размер утверждается
//! **до первого кадра**, командой `window::resize` — система создаёт окно каким
//! ей удобно. Второе: `on_resized` не вызывается никогда. Окно не растягивается
//! ни уголком, ни краем, значит всякое `Resized` — либо эхо собственной
//! команды, либо бухгалтерия оконной системы, и принять его за истину значит
//! получить два спорящих источника размера.
//!
//! # Правило раскладки, из которого следует всё остальное
//!
//! Растянутый ребёнок внутри группы «по содержимому» **схлопывается в ноль**;
//! так устроен `iced 0.12`, и это записано в самом ките. Ноль означает квад
//! нулевого размера, а его рендерер не принимает: в отладочной сборке —
//! паника, в рабочей — испорченная маска отсечения и тёмные прямоугольники
//! поверх соседних виджетов.
//!
//! Отсюда порядок: **каждый** контейнер на пути от окна до содержимого
//! объявляет свой размер явно. Ни одного «по умолчанию разберётся».

pub mod message;
pub mod state;
pub mod update;

use std::time::{Duration, Instant};

use iced::widget::{column, container, row};
use iced::{Element, Length, Point, Size, Subscription, Task, Theme, window};
use uikit::ThemeType;
use uikit::layout::gap;
use uikit::widgets::Tabs;
use uikit::window::{Anchor, Morph, WindowChrome};

pub use self::message::{Message, Screen};
pub use self::state::State;
use crate::screens;

/// Размер в покое.
///
/// Квадрат с ладонь: панель, строка состояния и кнопка — больше в клиенте,
/// открытом ради одного нажатия, ничего и не нужно.
pub const COMPACT: Size = Size::new(360.0, 400.0);

/// Размер с раскрытой панелью.
pub const EXPANDED: Size = Size::new(800.0, 600.0);

/// Отступ от края окна до содержимого.
pub const PAGE_PADDING: f32 = 16.0;

/// Зазор между вкладками — и всюду, где что-то стоит под полосой вкладок.
///
/// Одно число на оба расстояния, и задаётся оно полосе вкладок явно, а не
/// берётся из её умолчания: пока это два разных числа, кнопка под полосой
/// отстоит от неё не так, как вкладки отстоят друг от друга, и полоса
/// перестаёт читаться как ряд с остальным содержимым вкладки.
pub const TAB_GAP: f32 = 6.0;

/// Шаг кадра, пока окно едет.
///
/// Шестьдесят кадров в секунду: реже — движение видно ступеньками, чаще —
/// работа впустую, монитор всё равно не покажет.
const FRAME: Duration = Duration::from_millis(16);

/// Окно клиента.
pub struct App {
    state: State,
    chrome: WindowChrome,
    morph: Morph,
    theme: ThemeType,
    /// Идентификатор главного окна.
    ///
    /// В `iced 0.14` его больше не заменяет константа `window::Id::MAIN`: окно
    /// создаёт исполнитель, и настоящий идентификатор приходит событием
    /// [`window::Event::Opened`]. До него команды окну (`resize`, `drag`,
    /// `close`) уходят в никуда, поэтому на его месте до открытия стоит
    /// временный `Id::unique()` — заведомо не тот, но нужный, чтобы `view`
    /// собрал шапку уже на первом кадре.
    window: window::Id,
}

impl App {
    /// Создаёт окно и первую команду.
    pub fn new(theme: ThemeType) -> (Self, Task<Message>) {
        let mut state = State {
            palette: theme.to_iced_theme().palette(),
            ..State::default()
        };

        // Первый кадр рисуется раньше, чем придёт ответ от службы. Показать в
        // нём «Служба не отвечает» значило бы обвинить её до того, как её
        // вообще спросили.
        state.connection.starting = true;

        // Заставку заводим здесь, а не в `State::default`: печатается она ровно
        // один раз, при открытии окна, а `default` берут ещё и тесты, и
        // раскрытая панель — им анимация ни к чему.
        state.boot = state::Boot::begin();

        let app = Self {
            state,
            chrome: WindowChrome::new(),
            morph: Morph::new(COMPACT)
                .with_anchor(Anchor::Center)
                .with_bounds(COMPACT, EXPANDED),
            theme,
            // Размер окна задаёт `window::Settings` при создании (см. [`crate`]
            // `run`), поэтому отдельная команда `resize` до первого кадра
            // больше не нужна: настоящий идентификатор для неё всё равно ещё
            // неизвестен.
            window: window::Id::unique(),
        };

        (app, update::bootstrap())
    }

    /// Заголовок окна.
    pub fn title(&self) -> String {
        "Ostriacki Pingwin".to_owned()
    }

    /// Разбирает сообщение.
    pub fn update(&mut self, message: Message) -> Task<Message> {
        update::handle(self, message)
    }

    /// Собирает окно.
    pub fn view(&self) -> Element<'_, Message> {
        let header = uikit::window::header(self.window, "Ostriacki Pingwin")
            .on_close(Message::Window(message::WindowMessage::Close))
            .on_minimize(Message::Window(message::WindowMessage::Minimize))
            // Разворачивать окну нечего: размером владеет `Morph`, и во весь
            // экран оно показало бы ровно то же самое и вдобавок экран
            // пустого места. Кнопки нет совсем — мёртвая зелёная обещала бы
            // действие, которого не будет.
            .without_maximize()
            .extra(
                // Два кружка одного вида: правая часть шапки — место для
                // действий над самим окном, и разнокалиберные значки рядом со
                // «светофором» читались бы как чужие.
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

        // Обе оси заданы явно: `iced::widget::Column` по умолчанию «по
        // содержимому», а оба ребёнка объявляют себя растянутыми.
        let root = column![header, body]
            .width(Length::Fill)
            .height(Length::Fill);

        container(root)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(uikit::style::container::window_root_seamless as fn(&Theme) -> _)
            .into()
    }

    /// Тема окна.
    pub fn theme(&self) -> Theme {
        self.theme.to_iced_theme()
    }

    /// Подписки окна.
    pub fn subscription(&self) -> Subscription<Message> {
        let mut streams = vec![
            crate::ipc::subscription::events(),
            // События окна нужны рамке: без них не работает перетаскивание.
            // Третий аргумент — идентификатор окна: в `iced 0.14` он приезжает
            // сюда, а не в самом `Event::Window`.
            iced::event::listen_with(|event, status, window_id| match event {
                iced::Event::Mouse(iced::mouse::Event::CursorMoved { position }) => Some(
                    Message::Window(message::WindowMessage::CursorMoved(position)),
                ),
                // Нажатие, которое взял себе виджет, окну не достаётся:
                // щелчок по кружку в шапке — это действие, а не попытка
                // утащить окно.
                iced::Event::Mouse(iced::mouse::Event::ButtonPressed(
                    iced::mouse::Button::Left,
                )) if status == iced::event::Status::Ignored => {
                    Some(Message::Window(message::WindowMessage::DragStarted))
                }
                iced::Event::Mouse(iced::mouse::Event::ButtonReleased(
                    iced::mouse::Button::Left,
                )) => Some(Message::Window(message::WindowMessage::DragStopped)),
                // Окно открылось — здесь узнаётся его настоящий идентификатор и
                // исходное положение (`Morph` держит на месте центр и обязан
                // знать, откуда окно растёт).
                iced::Event::Window(iced::window::Event::Opened { position, size }) => Some(
                    Message::Window(message::WindowMessage::Opened(window_id, position, size)),
                ),
                iced::Event::Window(iced::window::Event::Moved(point)) => Some(Message::Window(
                    message::WindowMessage::Moved(point.x as i32, point.y as i32),
                )),
                _ => None,
            }),
        ];

        // Кадры нужны, только пока что-то движется: окно едет пружиной или
        // печатается заставка. На замершем окне таймер кадров — это разбуженный
        // процессор ни за чем.
        if !self.morph.settled() || self.state.boot.typing() {
            streams.push(iced::time::every(FRAME).map(Message::Frame));
        } else if !self.state.expanded {
            // Допечатали, и всё замерло — кроме курсора консоли. Ему хватает
            // двух пробуждений в секунду вместо шестидесяти, и просит он их
            // только пока консоль на экране: под раскрытой панелью её не видно.
            streams.push(iced::time::every(state::BLINK).map(Message::Frame));
        }

        Subscription::batch(streams)
    }

    /// Идентификатор главного окна.
    pub fn window(&self) -> window::Id {
        self.window
    }

    /// Запоминает открытое окно: его идентификатор и, для `Morph`, положение.
    pub fn window_opened(&mut self, id: window::Id, position: Option<Point>, size: Size) {
        self.window = id;
        self.morph.on_opened(position, size);
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
        self.morph.aim(if self.state.expanded {
            EXPANDED
        } else {
            COMPACT
        });
    }

    /// Переключает тему на следующую.
    ///
    /// Палитра в состоянии обновляется здесь же: `view` темы не получает, и,
    /// разъехавшись однажды, цвет текста остался бы от прежней темы до
    /// перезапуска.
    pub fn next_theme(&mut self) -> ThemeType {
        self.theme = self.theme.next();
        self.state.palette = self.theme.to_iced_theme().palette();
        self.theme
    }

    /// Окно в покое.
    fn compact(&self) -> Element<'_, Message> {
        container(screens::compact::view(&self.state))
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(PAGE_PADDING)
            .into()
    }

    /// Окно с раскрытой панелью.
    fn expanded(&self) -> Element<'_, Message> {
        let tabs = container(
            Tabs::new(crate::i18n::s().screens, self.state.screen.index())
                .spacing(TAB_GAP)
                .on_select(|index| Message::Screen(Screen::from_index(index)))
                .build(),
        )
        // Воздух сверху: полоса вкладок, приклеенная к шапке, читается как её
        // продолжение, а не как отдельный ряд. Снизу — ровно тот же зазор, что
        // между самими вкладками: содержимое вкладки начинается от полосы на
        // таком же расстоянии, на каком вкладки стоят друг от друга.
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
        // Клиент открывают ради одного нажатия; окно с почтовую марку и окно
        // в пол-экрана одинаково неудобны.
        const { assert!(COMPACT.width >= 300.0 && COMPACT.width <= 400.0) };
        const { assert!(COMPACT.height >= 300.0 && COMPACT.height <= 440.0) };
    }

    #[test]
    fn the_panel_is_bigger_in_both_directions() {
        // Иначе `Morph` поехал бы в одну сторону и вернулся в другую.
        const { assert!(EXPANDED.width > COMPACT.width) };
        const { assert!(EXPANDED.height > COMPACT.height) };
    }

    #[test]
    fn tab_labels_match_the_screens() {
        // Расхождение числа вкладок и числа экранов означало бы, что часть
        // экранов недостижима, а часть вкладок открывает не то.
        assert_eq!(crate::i18n::s().screens.len(), Screen::ALL.len());
    }
}
