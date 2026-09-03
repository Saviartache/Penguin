//! Разбор сообщений по областям. Один общий match на всё приложение нечитаем.
//!
//! Верхний уровень только раскладывает сообщения по адресатам; вся работа —
//! в файлах рядом. Так `match` остаётся коротким и не превращается в файл на
//! тысячу строк, куда никто не заглядывает без крайней нужды.

pub mod connection;
pub mod profiles;
pub mod rules;
pub mod settings;

use iced::{Task, window};
use penguin_ipc::schema::Request;

use crate::app::App;
use crate::app::message::{HomeMessage, IpcMessage, Message, WindowMessage};

/// Разбирает сообщение.
pub fn handle(app: &mut App, message: Message) -> Task<Message> {
    match message {
        Message::Window(window_message) => handle_window(app, window_message),
        Message::Screen(screen) => {
            app.state_mut().screen = screen;
            // Список приложений спрашивается при открытии экрана правил, а не
            // держится обновляемым: он нужен только там и меняется постоянно.
            if screen == crate::app::Screen::SplitTunnel {
                return rules::request_processes();
            }
            Task::none()
        }
        Message::ThemeToggle => {
            let theme = app.next_theme();
            crate::theme::save(theme);
            Task::none()
        }
        Message::PanelToggled => {
            app.toggle_panel();
            Task::none()
        }
        Message::Frame(now) => app.tick(now),

        Message::Ipc(ipc) => connection::handle(app, ipc),
        Message::Home(home) => connection::handle_home(app, home),
        Message::Servers(servers) => profiles::handle(app, servers),
        Message::SplitTunnel(split) => rules::handle(app, split),
        Message::Settings(settings) => settings::handle(app, settings),
    }
}

/// Разбирает управление окном.
///
/// Своя рамка вместо системной означает, что перетаскивание и изменение
/// размера — забота приложения. Всё состояние этого держит `WindowChrome`;
/// здесь только передача событий.
fn handle_window(app: &mut App, message: WindowMessage) -> Task<Message> {
    match message {
        // Окно открылось: запоминаем его настоящий идентификатор и исходное
        // положение. До этого команды окну уходили в никуда — настоящего id
        // ещё не было.
        WindowMessage::Opened(id, position, size) => {
            app.window_opened(id, position, size);
            Task::none()
        }
        // Только заряжаем: тащить начнёт `on_cursor_moved`, когда курсор
        // уедет дальше порога. Начать перетаскивание прямо на нажатии значит
        // утащить окно при щелчке по переключателю темы в той же шапке.
        WindowMessage::DragStarted => {
            let id = app.window();
            app.chrome_mut().arm_drag(id);
            Task::none()
        }
        WindowMessage::CursorMoved(position) => app.chrome_mut().on_cursor_moved(position),
        WindowMessage::Minimize => window::minimize(app.window(), true),
        WindowMessage::Close => window::close(app.window()),
        // Окно передвинули — `Morph` держит на месте центр и обязан знать, где
        // окно сейчас.
        WindowMessage::Moved(x, y) => {
            app.morph_mut().on_moved(x, y);
            Task::none()
        }
        // Кнопку отпустили: заряженное перетаскивание так им и не стало —
        // иначе следующее движение курсора где угодно по окну утащило бы его
        // за собой.
        WindowMessage::DragStopped => {
            app.chrome_mut().disarm_drag();
            Task::none()
        }
    }
}

/// Что окно делает сразу после открытия.
///
/// Сначала служба, потом вопросы к ней. Настройки, список профилей, состояние
/// тоннеля — всё это у неё, и без неё окно пустое; предлагать человеку
/// запустить её самому значит перекладывать на него нашу работу.
///
/// Прав это стоит один раз: служба ставится с автозапуском и дальше поднимается
/// вместе с системой, так что при следующих запусках UAC не появится.
pub fn bootstrap() -> Task<Message> {
    Task::perform(connection::ensure_at_startup(), |ready| {
        Message::Home(HomeMessage::ServiceChecked(ready))
    })
}

/// Спрашивает у демона всё, без чего окно пусто.
pub fn request_initial_state() -> Task<Message> {
    Task::batch([request(Request::GetConfig), request(Request::Status)])
}

/// Отправляет запрос демону.
///
/// Ошибка связи превращается в ответ об ошибке: у интерфейса один путь
/// обработки, и разводить «отказал» и «не ответил» по разным веткам незачем.
pub fn request(request: Request) -> Task<Message> {
    Task::perform(crate::ipc::client::send_or_error(request), |response| {
        Message::Ipc(IpcMessage::Response(Box::new(response)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_asks_for_config_and_status() {
        // Без настроек экраны нечем наполнить, без состояния — нечего
        // показать на главном.
        let command = request_initial_state();
        // `Task` не разбирается снаружи; проверяем хотя бы, что он не
        // пустой — пустой означал бы окно, которое ничего не спросило.
        assert!(!format!("{command:?}").contains("None"));
    }
}
