//! Состояние приложения как композиция состояний экранов, а не один плоский
//! набор полей.
//!
//! Плоский набор полей растёт вместе с числом экранов и через полгода
//! перестаёт отвечать на вопрос «что из этого кому нужно». Композиция
//! отвечает: поле экрана трогает только этот экран.
//!
//! Отдельно стоит [`Connection`] — то, что приходит от демона. Это не
//! состояние интерфейса, а его отражение, и правит его только поток событий.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use penguin_config::RootConfig;
use penguin_core::state::TunnelState;
use penguin_core::stats::{Throughput, Traffic};
use penguin_ipc::schema::{AppInfo, Explanation, LogLevel, StatusReport};

use crate::app::message::Screen;
use crate::forms::rule::Draft as RuleDraft;
use crate::forms::server::Draft as ServerDraft;

/// Сколько строк журнала держать в окне.
///
/// Журнал в интерфейсе — не архив, а последнее, что произошло; полный лежит в
/// файле у демона.
///
/// Пятьсот, а не двести: каждое соединение пишет строку, а браузер на живой
/// странице открывает их десятками. На двухстах строках журнал показывал бы
/// последние несколько секунд, и подъём тоннеля уезжал бы из него раньше, чем
/// человек успеет открыть вкладку.
pub const LOG_CAPACITY: usize = 500;

/// Сколько отсчётов скорости показывать на графике.
pub const GRAPH_POINTS: usize = 60;

/// Сколько печатается панель при первом открытии.
///
/// Меньше секунды: это заставка, а не ожидание. Дольше — и человек, пришедший
/// нажать одну кнопку, смотрит на анимацию вместо дела.
const BOOT: Duration = Duration::from_millis(750);

/// Полупериод мигания курсора.
///
/// Два пробуждения в секунду. Правило «никакого таймера на замершем окне»
/// писалось про кадры пружины — шестьдесят в секунду; здесь на четыре порядка
/// меньше работы, а курсор, который не мигает, читается как замёрзшее окно.
pub const BLINK: Duration = Duration::from_millis(500);

/// Всё состояние окна.
#[derive(Debug)]
pub struct State {
    /// Открытый экран раскрытой панели.
    pub screen: Screen,
    /// Панель раскрыта.
    ///
    /// В покое окно — квадрат с панелью и кнопкой; за настройками оно
    /// раскрывается и показывает вкладки.
    pub expanded: bool,
    /// Палитра текущей темы.
    ///
    /// Держится здесь, потому что `view` темы не получает, а в `iced 0.12`
    /// цвет текста задаётся конкретным значением, а не ссылкой на тему.
    /// Пересчитывается при смене темы — там же, где тема и меняется.
    pub palette: iced::theme::Palette,
    /// Что приходит от демона.
    pub connection: Connection,
    /// Настройки, какими их правит окно.
    pub config: RootConfig,
    /// Настройки, какими их в последний раз принял демон.
    ///
    /// Отдельно от `config`, потому что несохранённое в окне есть ровно одно —
    /// набор правил. Всё остальное — выбор профиля, переключатели настроек —
    /// уезжает демону сразу, и уехать оно обязано **без** этих правил: иначе
    /// щелчок по чужой вкладке молча сохраняет то, что человек ещё правит.
    /// Именно отсюда берётся `routing` при таком сохранении.
    pub saved: RootConfig,
    /// Есть ли несохранённые правила.
    ///
    /// Только правила: они одни копятся в окне и ждут «Сохранить». Настройки и
    /// профили сохраняются сразу — предлагать «Сохранить» тому, что уже
    /// сохранено, значит превратить кнопку в украшение.
    pub dirty: bool,
    /// Состояние экрана раздельного тоннелирования.
    pub split_tunnel: SplitTunnelState,
    /// Состояние экрана серверов.
    pub servers: ServersState,
    /// Печатающая заставка при первом открытии.
    pub boot: Boot,
}

impl Default for State {
    fn default() -> Self {
        Self {
            screen: Screen::default(),
            expanded: false,
            palette: uikit::ThemeType::default().to_iced_theme().palette(),
            connection: Connection::default(),
            config: RootConfig::default(),
            saved: RootConfig::default(),
            dirty: false,
            split_tunnel: SplitTunnelState::default(),
            servers: ServersState::default(),
            // По умолчанию заставки нет: тесты и раскрытая панель показывают
            // содержимое целиком. Печатать её просит только `App::new`.
            boot: Boot::idle(),
        }
    }
}

/// Печатающая заставка главного экрана.
///
/// Панель при первом открытии печатается знак за знаком, как загрузка DOS.
/// Здесь только точка отсчёта: долю напечатанного считает время, а не счётчик в
/// сообщениях, — так анимация не зависит от того, с какой частотой приходят
/// кадры.
#[derive(Debug, Default, Clone, Copy)]
pub struct Boot {
    /// Когда началась печать. `None` — заставки нет, панель показывается сразу
    /// целиком.
    started: Option<Instant>,
}

impl Boot {
    /// Заставки нет.
    pub fn idle() -> Self {
        Self { started: None }
    }

    /// Запускает печать от текущего момента.
    pub fn begin() -> Self {
        Self {
            started: Some(Instant::now()),
        }
    }

    /// Доля напечатанного, `0.0..=1.0`. `None` — печатать нечего, панель
    /// показывается целиком.
    pub fn progress(&self) -> Option<f32> {
        let started = self.started?;
        let fraction = started.elapsed().as_secs_f32() / BOOT.as_secs_f32();
        Some(fraction.clamp(0.0, 1.0))
    }

    /// Виден ли курсор в этот момент.
    ///
    /// Считается временем, а не переключается сообщением: у мигания нет
    /// состояния, которое стоило бы хранить и с которым можно было бы
    /// разойтись.
    pub fn cursor(&self) -> bool {
        let Some(started) = self.started else {
            // Заставки не было — курсор просто стоит. Так его видят тесты и
            // так он выглядит, если мигать нечем.
            return true;
        };
        (started.elapsed().as_millis() / BLINK.as_millis()) % 2 == 0
    }

    /// Идёт ли печать сейчас.
    ///
    /// Пока идёт — окну нужен таймер кадров; как только допечатали, таймер
    /// гаснет, и замершее окно больше не будит процессор. Запас в один кадр —
    /// чтобы последний кадр гарантированно показал панель целиком.
    pub fn typing(&self) -> bool {
        self.started
            .is_some_and(|started| started.elapsed() < BOOT + Duration::from_millis(32))
    }
}

/// Отражение того, что происходит у демона.
#[derive(Debug, Default)]
pub struct Connection {
    /// Связь с демоном есть.
    pub online: bool,
    /// Служба сейчас поднимается.
    ///
    /// Отдельно от `online`: пока идёт установка, связи ещё нет — но кричать
    /// «Служба не отвечает» рано, всё идёт по плану.
    pub starting: bool,
    /// Служба сейчас гасится — окно закрывается.
    ///
    /// Отдельно от `starting` по той же причине, по какой тот отдельно от
    /// `online`: связи уже нет, но это мы сами её и убрали.
    pub stopping: bool,
    /// Почему связи нет.
    pub error: Option<String>,
    /// Состояние тоннеля.
    ///
    /// Время работы в нём — то, что сообщил демон, и с той минуты оно не
    /// менялось. Показывать надо [`Self::tunnel_now`].
    pub tunnel: TunnelState,
    /// Момент, от которого идёт время работы тоннеля.
    ///
    /// Демон присылает состояние только когда оно меняется, а секунды идут
    /// всё время. Поэтому окно считает их само — от точки, которую вычислило
    /// по последнему сообщению демона: его цифра остаётся главной, но между
    /// сообщениями счётчик не стоит.
    since: Option<std::time::Instant>,
    /// Счётчики.
    pub traffic: Traffic,
    /// Мгновенная скорость.
    pub rate: Throughput,
    /// Сколько соединений открыто.
    pub connections: u64,
    /// История скорости для графика.
    pub graph: VecDeque<Throughput>,
    /// Журнал.
    pub log: VecDeque<LogLine>,
    /// Тот же журнал строками — таким его берёт символьная консоль.
    ///
    /// Отдельно от `log`, а не собирается на лету: консоль кита берёт строки
    /// **взаймы**, а собранный в `view` временный список умирает раньше, чем
    /// виджет успевает нарисоваться.
    pub lines: Vec<String>,
}

impl Connection {
    /// Принимает свежее состояние.
    pub fn apply_status(&mut self, status: &StatusReport) {
        self.online = true;
        self.error = None;
        self.set_tunnel(status.state.clone());
        self.traffic = status.traffic;
        self.connections = status.connections;
    }

    /// Принимает новое состояние тоннеля.
    ///
    /// Единственный путь, которым оно меняется: точка отсчёта времени работы
    /// обязана обновляться вместе с ним, а два места, где это делается,
    /// однажды разойдутся.
    pub fn set_tunnel(&mut self, state: TunnelState) {
        self.since = match &state {
            TunnelState::Connected { uptime_secs, .. } => {
                // Отматываем назад на то, что насчитал демон: окно могли
                // открыть на тоннеле, поднятом час назад.
                std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_secs(*uptime_secs))
                    .or_else(|| Some(std::time::Instant::now()))
            }
            _ => None,
        };
        self.tunnel = state;
    }

    /// Состояние тоннеля с досчитанным временем работы.
    ///
    /// То, что показывают: в `tunnel` лежит цифра на момент последнего
    /// сообщения демона, и без досчёта окно показывало бы `0:00` всё время,
    /// пока тоннель работает.
    pub fn tunnel_now(&self) -> TunnelState {
        match (&self.tunnel, self.since) {
            (TunnelState::Connected { profile, .. }, Some(since)) => TunnelState::Connected {
                profile: profile.clone(),
                uptime_secs: since.elapsed().as_secs(),
            },
            (other, _) => other.clone(),
        }
    }

    /// Принимает замер скорости.
    pub fn apply_throughput(&mut self, rate: Throughput, total: Traffic, connections: u64) {
        self.rate = rate;
        self.traffic = total;
        self.connections = connections;

        if self.graph.len() == GRAPH_POINTS {
            self.graph.pop_front();
        }
        self.graph.push_back(rate);
    }

    /// Добавляет строку в журнал.
    pub fn push_log(&mut self, level: LogLevel, message: String) {
        if self.log.len() == LOG_CAPACITY {
            self.log.pop_front();
            self.lines.remove(0);
        }

        // Уровень ставится в начало строки: консоль кита красит строки по
        // приметам в тексте, а угаданный уровень — это ошибка, покрашенная как
        // обычная запись, ровно тогда, когда она важнее всего.
        self.lines.push(match mark(level) {
            Some(label) => format!("{label} {message}"),
            None => message.clone(),
        });
        self.log.push_back(LogLine { level, message });
    }

    /// Окно само сейчас возится со службой: ставит, запускает или гасит её.
    ///
    /// Пока это идёт, спрашивать службу бессмысленно и вредно. Отвечать
    /// некому — она либо ещё не поднялась, либо уже опускается, — а каждая
    /// неудачная попытка означает «Служба не отвечает» на экране ровно в тот
    /// момент, когда поверх окна открыт запрос пароля администратора.
    pub fn is_busy_with_service(&self) -> bool {
        self.starting || self.stopping
    }

    /// Отмечает потерю связи.
    ///
    /// Состояние тоннеля при этом обнуляется: показывать «подключено», когда
    /// демона нет, значит врать — тоннеля мы больше не видим.
    pub fn mark_offline(&mut self, reason: impl Into<String>) {
        self.online = false;
        self.error = Some(reason.into());
        self.set_tunnel(TunnelState::Disconnected);
        self.rate = Throughput::default();
        self.connections = 0;
    }

    /// Наибольшая скорость на графике — шкала.
    ///
    /// Без общей шкалы вертикаль прыгала бы на каждом кадре, подстраиваясь
    /// под текущий максимум.
    pub fn graph_scale(&self) -> u64 {
        self.graph
            .iter()
            .map(|point| point.up_bps.max(point.down_bps))
            .max()
            // Пустой график всё равно должен на что-то делиться.
            .unwrap_or(1)
            .max(1)
    }
}

/// Приставка уровня в строке журнала.
///
/// Свободная функция с тестом: молчаливая ошибка в журнале — это ошибка,
/// которую не заметили.
pub fn mark(level: LogLevel) -> Option<&'static str> {
    match level {
        LogLevel::Error => Some(crate::i18n::s().level_error),
        LogLevel::Warning => Some(crate::i18n::s().level_warning),
        // Обычные строки идут без приставки: стена одинаковых меток — это шум,
        // за которым не видно двух строк, ради которых журнал и открыли.
        LogLevel::Info => None,
    }
}

/// Строка журнала.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Насколько это важно.
    pub level: LogLevel,
    /// Текст.
    pub message: String,
}

/// Экран раздельного тоннелирования.
#[derive(Debug, Default)]
pub struct SplitTunnelState {
    /// Поиск по списку правил.
    pub search: String,
    /// Открыт ли черновик нового правила. `None` — окно закрыто.
    ///
    /// Форма живёт в модальном окне, а не под списком: девять полей под
    /// таблицей отодвигают её за нижний край, и человек пишет правило, не видя
    /// тех, что уже есть, — тогда как новое правило почти всегда пишут, глядя
    /// на соседнее.
    pub editor: Option<RuleDraft>,
    /// Открыто ли окно проверки.
    ///
    /// Отдельный признак, а не `Option` с полями: поля проверки переживают
    /// закрытие окна намеренно — проверяют обычно одно и то же соединение по
    /// нескольку раз, правя правила между заходами.
    pub probe_open: bool,
    /// Адрес для проверки правил.
    pub probe_destination: String,
    /// Приложение для проверки.
    pub probe_process: String,
    /// Что ответила проверка.
    pub probe_result: Option<Explanation>,
    /// Список запущенных приложений — для выбора.
    pub running_apps: Vec<AppInfo>,
    /// Поиск по списку приложений.
    pub app_search: String,
}

/// Экран серверов.
#[derive(Debug, Default)]
pub struct ServersState {
    /// Поиск по списку профилей.
    pub search: String,
    /// Задержки до профилей.
    pub latencies: Vec<(String, Option<u32>)>,
    /// Идёт проверка.
    pub probing: bool,
    /// Открытый редактор профиля. `None` — редактор закрыт.
    pub editor: Option<ServerDraft>,
    /// Вставленная ссылка-приглашение.
    ///
    /// Не в черновике: черновик описывает профиль, а ссылка — способ его
    /// заполнить. Живёт ровно столько, сколько открыт редактор.
    pub link: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn throughput(down: u64) -> Throughput {
        Throughput {
            up_bps: 0,
            down_bps: down,
        }
    }

    #[test]
    fn graph_keeps_a_fixed_window() {
        let mut connection = Connection::default();
        for step in 0..(GRAPH_POINTS as u64 * 3) {
            connection.apply_throughput(throughput(step), Traffic::default(), 0);
        }
        assert_eq!(connection.graph.len(), GRAPH_POINTS);
    }

    #[test]
    fn uptime_keeps_running_between_reports() {
        // Демон сообщает состояние только когда оно меняется, а секунды идут
        // всё время. Без досчёта окно навсегда застывало на `0:00`.
        let mut connection = Connection::default();
        connection.set_tunnel(TunnelState::Connected {
            profile: penguin_core::id::ProfileId::new("home"),
            uptime_secs: 90,
        });

        let TunnelState::Connected { uptime_secs, .. } = connection.tunnel_now() else {
            panic!("не подключено")
        };
        // Цифра демона — точка отсчёта, а не потолок.
        assert!(uptime_secs >= 90, "время работы ушло назад: {uptime_secs}");
    }

    #[test]
    fn a_dropped_tunnel_forgets_its_uptime() {
        // Иначе следующее подключение начнёт счёт с прошлого раза.
        let mut connection = Connection::default();
        connection.set_tunnel(TunnelState::Connected {
            profile: penguin_core::id::ProfileId::new("home"),
            uptime_secs: 500,
        });
        connection.mark_offline("служба остановлена");

        assert!(matches!(connection.tunnel_now(), TunnelState::Disconnected));
        connection.set_tunnel(TunnelState::Connected {
            profile: penguin_core::id::ProfileId::new("home"),
            uptime_secs: 0,
        });
        let TunnelState::Connected { uptime_secs, .. } = connection.tunnel_now() else {
            panic!("не подключено")
        };
        assert!(uptime_secs < 5, "счёт продолжился с прошлого раза");
    }

    #[test]
    fn log_keeps_a_fixed_window() {
        // Журнал в окне — последнее, что произошло; полный лежит у демона.
        let mut connection = Connection::default();
        for step in 0..(LOG_CAPACITY * 2) {
            connection.push_log(LogLevel::Info, format!("строка {step}"));
        }
        assert_eq!(connection.log.len(), LOG_CAPACITY);
        // Строки и их отрисованные копии обязаны идти вровень: разошедшись,
        // журнал в окне показывал бы одно, а его подписи — другое.
        assert_eq!(connection.lines.len(), LOG_CAPACITY);
        // Осталось именно последнее, а не первое.
        let last = format!("строка {}", LOG_CAPACITY * 2 - 1);
        assert_eq!(connection.log.back().expect("есть").message, last);
        assert_eq!(connection.lines.last().expect("есть"), &last);
    }

    #[test]
    fn losing_the_daemon_clears_the_tunnel_state() {
        // Показывать «подключено», когда демона нет, значит врать: тоннеля мы
        // больше не видим.
        let mut connection = Connection {
            tunnel: TunnelState::Connected {
                profile: penguin_core::id::ProfileId::new("home"),
                uptime_secs: 42,
            },
            connections: 7,
            ..Connection::default()
        };

        connection.mark_offline("служба остановлена");

        assert!(!connection.online);
        assert_eq!(connection.tunnel, TunnelState::Disconnected);
        assert_eq!(connection.connections, 0);
        assert!(connection.error.is_some());
    }

    #[test]
    fn graph_scale_never_divides_by_zero() {
        let connection = Connection::default();
        assert_eq!(connection.graph_scale(), 1);
    }

    #[test]
    fn graph_scale_follows_the_peak() {
        let mut connection = Connection::default();
        connection.apply_throughput(throughput(100), Traffic::default(), 0);
        connection.apply_throughput(throughput(5_000), Traffic::default(), 0);
        connection.apply_throughput(throughput(200), Traffic::default(), 0);
        assert_eq!(connection.graph_scale(), 5_000);
    }

    #[test]
    fn status_marks_the_connection_online() {
        let mut connection = Connection::default();
        connection.mark_offline("нет связи");

        connection.apply_status(&StatusReport {
            state: TunnelState::Disconnected,
            traffic: Traffic::default(),
            rate: Throughput::default(),
            connections: 0,
            rules: 0,
            mode: "full".to_owned(),
            rtt: None,
        });

        assert!(connection.online);
        assert!(connection.error.is_none());
    }
}
