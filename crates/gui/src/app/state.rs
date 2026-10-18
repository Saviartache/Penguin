//! Состояние приложения как композиция состояний экранов.
//!
//! Отдельно стоит [`Connection`] — отражение демона, правит его только поток событий.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use penguin_config::RootConfig;
use penguin_core::state::TunnelState;
use penguin_core::stats::{Throughput, Traffic};
use penguin_ipc::schema::{AppInfo, Explanation, LogLevel, StatusReport};

use crate::app::message::Screen;
use crate::forms::flow::{Flow, FlowRule};
use crate::forms::rule::{Draft as RuleDraft, Section as RuleSection};
use crate::forms::server::Draft as ServerDraft;

/// Строк журнала в окне; полный журнал лежит у демона.
pub const LOG_CAPACITY: usize = 500;

/// Отсчётов скорости в окне истории (по нему считается шкала).
pub const GRAPH_POINTS: usize = 60;

/// Сколько печатается заставка при первом открытии.
const BOOT: Duration = Duration::from_millis(750);

/// Всё состояние окна.
#[derive(Debug)]
pub struct State {
    /// Открытый экран раскрытой панели.
    pub screen: Screen,
    /// Панель раскрыта.
    pub expanded: bool,
    /// Палитра темы: `view` темы не получает.
    pub palette: iced::theme::Palette,
    /// Что приходит от демона.
    pub connection: Connection,
    /// Настройки, какими их правит окно.
    pub config: RootConfig,
    /// Настройки, как их принял демон. Несохранённое в окне — только правила,
    /// остальное уезжает сразу и обязано уехать без них; `routing` берётся отсюда.
    pub saved: RootConfig,
    /// Есть несохранённые правила.
    pub dirty: bool,
    /// Экран раздельного тоннелирования.
    pub split_tunnel: SplitTunnelState,
    /// Экран журнала.
    pub logs: LogsState,
    /// Экран серверов.
    pub servers: ServersState,
    /// Печатающая заставка.
    pub boot: Boot,
    /// Обновление программы.
    pub updates: Updates,
    /// Открыт список профилей на компактном экране: первая видимая строка,
    /// дробная — трекпад листает долями строки.
    pub profile_menu: Option<f32>,
}

/// Что окно знает об обновлении.
#[derive(Debug, Default)]
pub struct Updates {
    /// Где дело.
    pub status: UpdateStatus,
    /// Проверка при запуске уже решалась: настройки приходят от демона не раз.
    pub startup_done: bool,
    /// Открыто окно с предложением обновиться.
    pub dialog: bool,
}

/// Ход обновления.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum UpdateStatus {
    /// Не спрашивали или спросили и тихо не вышло.
    #[default]
    Idle,
    /// Идёт проверка.
    Checking,
    /// Новее нет.
    Latest,
    /// Есть новый выпуск.
    Available(penguin_update::Available),
    /// Идёт скачивание и подмена.
    Installing,
    /// Установлено, окно перезапускается.
    Restarting,
    /// Не вышло: причина.
    Failed(String),
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
            logs: LogsState::default(),
            servers: ServersState::default(),
            boot: Boot::idle(),
            updates: Updates::default(),
            profile_menu: None,
        }
    }
}

/// Печатающая заставка; доля напечатанного считается по времени, не по кадрам.
#[derive(Debug, Default, Clone, Copy)]
pub struct Boot {
    /// `None` — заставки нет.
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

    /// Доля напечатанного, `0.0..=1.0`; `None` — показывать целиком.
    pub fn progress(&self) -> Option<f32> {
        let started = self.started?;
        let fraction = started.elapsed().as_secs_f32() / BOOT.as_secs_f32();
        Some(fraction.clamp(0.0, 1.0))
    }

    /// Нужен ли таймер кадров; запас в кадр, чтобы последний показал всё.
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
    /// Служба поднимается: связи нет, но так и задумано.
    pub starting: bool,
    /// Служба гасится вместе с окном.
    pub stopping: bool,
    /// Почему связи нет.
    pub error: Option<String>,
    /// Состояние тоннеля; показывать надо [`Self::tunnel_now`].
    pub tunnel: TunnelState,
    /// Перед подключением обновляется подписка: демон ещё не подключается,
    /// а окно уже показывает подключение. Сброс — отмена.
    pub reloading: bool,
    /// Точка отсчёта времени работы: демон шлёт состояние только при смене.
    since: Option<Instant>,
    /// Счётчики.
    pub traffic: Traffic,
    /// Мгновенная скорость.
    pub rate: Throughput,
    /// Открытых соединений.
    pub connections: u64,
    /// История скорости.
    pub graph: VecDeque<Throughput>,
    /// Журнал.
    pub log: VecDeque<LogLine>,
    /// Журнал строками для консоли кита: она берёт их взаймы.
    pub lines: Vec<String>,
    /// Сколько строк пришло за всё время: журнал ограничен, длина расти
    /// перестаёт, а консоли нужно знать, сколько записей новых.
    pub appended: u64,
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

    /// Принимает состояние тоннеля; единственный путь, обновляющий `since`.
    pub fn set_tunnel(&mut self, state: TunnelState) {
        self.since = match &state {
            TunnelState::Connected { uptime_secs, .. } => {
                // Окно могли открыть на тоннеле, поднятом час назад.
                Instant::now()
                    .checked_sub(Duration::from_secs(*uptime_secs))
                    .or_else(|| Some(Instant::now()))
            }
            _ => None,
        };
        self.tunnel = state;
    }

    /// Состояние тоннеля с досчитанным временем работы.
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
        self.push_line(level, message, None);
    }

    /// Добавляет решение по соединению: строку и то, из чего она собрана.
    pub fn push_flow(&mut self, flow: Flow) {
        self.push_line(LogLevel::Info, flow.line(), Some(flow));
    }

    fn push_line(&mut self, level: LogLevel, message: String, flow: Option<Flow>) {
        self.appended += 1;
        if self.log.len() == LOG_CAPACITY {
            self.log.pop_front();
            self.lines.remove(0);
        }

        // Консоль красит по тексту: уровень должен стоять в начале строки.
        self.lines.push(match mark(level) {
            Some(label) => format!("{label} {message}"),
            None => message.clone(),
        });
        self.log.push_back(LogLine {
            level,
            message,
            flow,
        });
    }

    /// Окно само возится со службой (ставит, запускает, гасит).
    pub fn is_busy_with_service(&self) -> bool {
        self.starting || self.stopping
    }

    /// Профиль менять нельзя: тоннель поднят или поднимается.
    pub fn locks_profile(&self) -> bool {
        self.reloading
            || !matches!(
                self.tunnel,
                TunnelState::Disconnected | TunnelState::Failed { .. }
            )
    }

    /// Отмечает потерю связи; «подключено» без демона было бы враньём.
    pub fn mark_offline(&mut self, reason: impl Into<String>) {
        self.online = false;
        self.error = Some(reason.into());
        self.set_tunnel(TunnelState::Disconnected);
        self.rate = Throughput::default();
        self.connections = 0;
    }

    /// Наибольшая скорость окна истории: общая шкала графика.
    pub fn graph_scale(&self) -> u64 {
        self.graph
            .iter()
            .map(|point| point.up_bps.max(point.down_bps))
            .max()
            .unwrap_or(1)
            .max(1)
    }
}

/// Приставка уровня в строке журнала; обычные строки идут без неё.
pub fn mark(level: LogLevel) -> Option<&'static str> {
    match level {
        LogLevel::Error => Some(crate::i18n::s().level_error),
        LogLevel::Warning => Some(crate::i18n::s().level_warning),
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
    /// Соединение, если строка — решение по нему.
    pub flow: Option<Flow>,
}

/// Экран журнала.
#[derive(Debug, Default)]
pub struct LogsState {
    /// Что скопировано — показывается плашкой, пока не сменится номер.
    pub copied: Option<(u64, String)>,
    /// Номер последнего копирования: гасит плашку только своё ожидание.
    pub copies: u64,
    /// Окно «Правило для соединения»; `None` — закрыто.
    pub rule: Option<FlowRule>,
}

/// Экран раздельного тоннелирования.
#[derive(Debug, Default)]
pub struct SplitTunnelState {
    /// Поиск по списку правил.
    pub search: String,
    /// Черновик правила в модальном окне; `None` — закрыто.
    pub editor: Option<RuleDraft>,
    /// Открыто окно проверки; поля проверки переживают закрытие.
    pub probe_open: bool,
    /// Адрес для проверки правил.
    pub probe_destination: String,
    /// Приложение для проверки.
    pub probe_process: String,
    /// Ответ проверки.
    pub probe_result: Option<Explanation>,
    /// Запущенные приложения — для выбора.
    pub running_apps: Vec<AppInfo>,
    /// Поиск по списку приложений.
    pub app_search: String,
    /// Открытый раздел окна группы.
    pub section: RuleSection,
    /// Поле адресов и портов: поиск по списку и новое значение.
    pub entry: String,
    /// Открыто системное окно выбора файла (чужое, второе открывать нельзя).
    pub picking: bool,
    /// Почему оно не открылось; показывается в окне правила.
    pub pick_error: Option<String>,
    /// Итог последнего импорта или экспорта; показывается над таблицей.
    pub import_report: Option<String>,
}

/// Экран серверов.
#[derive(Debug, Default)]
pub struct ServersState {
    /// Поиск по списку профилей.
    pub search: String,
    /// Задержки до профилей.
    pub latencies: Vec<(String, Option<u32>)>,
    /// Очередь проверки: серверы по одному.
    pub probe: crate::app::probe_queue::ProbeQueue,
    /// Открыт выбор протокола (первый шаг «Добавить сервер»).
    pub picker: bool,
    /// Открытый редактор профиля; `None` — закрыт.
    pub editor: Option<ServerDraft>,
    /// Вставленная ссылка-приглашение; живёт, пока открыт редактор.
    pub link: String,
    /// Открыт выбор способа добавить WireGuard (вручную, `.conf`, подпиской).
    pub wireguard: bool,
    /// Ключ подписки в окне добавления WireGuard.
    pub subscription_key: String,
    /// Идёт работа в окне (обновление подписки или чтение `.conf`): кнопки заблокированы.
    pub subscription_busy: bool,
    /// Страны серверов для флагов.
    pub countries: crate::app::countries::Countries,
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
        let mut connection = Connection::default();
        connection.set_tunnel(TunnelState::Connected {
            profile: penguin_core::id::ProfileId::new("home"),
            uptime_secs: 90,
        });

        let TunnelState::Connected { uptime_secs, .. } = connection.tunnel_now() else {
            panic!("не подключено")
        };
        assert!(uptime_secs >= 90, "время работы ушло назад: {uptime_secs}");
    }

    #[test]
    fn a_dropped_tunnel_forgets_its_uptime() {
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
        let mut connection = Connection::default();
        for step in 0..(LOG_CAPACITY * 2) {
            connection.push_log(LogLevel::Info, format!("строка {step}"));
        }
        assert_eq!(connection.log.len(), LOG_CAPACITY);
        // Строки и их копии для консоли идут вровень.
        assert_eq!(connection.lines.len(), LOG_CAPACITY);
        let last = format!("строка {}", LOG_CAPACITY * 2 - 1);
        assert_eq!(connection.log.back().expect("есть").message, last);
        assert_eq!(connection.lines.last().expect("есть"), &last);
    }

    #[test]
    fn losing_the_daemon_clears_the_tunnel_state() {
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
            mode: "tunnel".to_owned(),
            rtt: None,
        });

        assert!(connection.online);
        assert!(connection.error.is_none());
    }
}
