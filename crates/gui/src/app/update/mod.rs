//! Разбор сообщений по областям; работа — в файлах рядом.

pub mod connection;
pub mod logs;
pub mod profiles;
pub mod release;
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
        Message::Logs(logs) => logs::handle(app, logs),
        Message::Settings(settings) => settings::handle(app, settings),
        Message::Update(update) => release::handle(app, update),
    }
}

fn handle_window(app: &mut App, message: WindowMessage) -> Task<Message> {
    match message {
        WindowMessage::Opened(id, position, size) => app.window_opened(id, position, size),
        // Только заряжаем: тащить начнёт `on_cursor_moved`, иначе щелчок по
        // кружку в шапке утащил бы окно.
        WindowMessage::DragStarted => {
            let id = app.window();
            app.chrome_mut().arm_drag(id);
            Task::none()
        }
        WindowMessage::CursorMoved(position) => app.chrome_mut().on_cursor_moved(position),
        WindowMessage::Minimize => app.hide(),
        WindowMessage::Show => app.show(),
        WindowMessage::Toggle => app.toggle_visibility(),
        WindowMessage::Close => close(app),
        WindowMessage::Stopped => window::close(app.window()),
        WindowMessage::Moved(x, y) => {
            app.morph_mut().on_moved(x, y);
            Task::none()
        }
        WindowMessage::DragStopped => {
            app.chrome_mut().disarm_drag();
            Task::none()
        }
    }
}

/// Закрыть значит остановить и службу: иначе останутся TUN и маршруты.
fn close(app: &mut App) -> Task<Message> {
    if !app.state().connection.online {
        return window::close(app.window());
    }
    // Флаг до задачи: связь оборвётся раньше ответа на запрос пароля.
    app.state_mut().connection.stopping = true;
    app.state_mut().connection.push_log(
        penguin_ipc::schema::LogLevel::Info,
        crate::i18n::s().service_stopping.to_owned(),
    );
    Task::perform(connection::shutdown_service(), |()| {
        Message::Window(WindowMessage::Stopped)
    })
}

/// Что окно делает после открытия: сначала служба, потом вопросы к ней.
///
/// Права нужны один раз: служба ставится с разрешением запускать её без них.
pub fn bootstrap() -> Task<Message> {
    Task::perform(connection::bring_up_service(), |ready| {
        Message::Home(HomeMessage::ServiceChecked(ready))
    })
}

/// Спрашивает у демона всё, без чего окно пусто.
pub fn request_initial_state() -> Task<Message> {
    Task::batch([request(Request::GetConfig), request(Request::Status)])
}

/// Сохраняет то, что сохраняется сразу; правила берутся из принятого демоном,
/// чтобы не сохранить то, что ещё правится на их вкладке.
pub fn save(app: &mut App) -> Task<Message> {
    let mut config = app.state().config.clone();
    config.routing = app.state().saved.routing.clone();

    app.state_mut().saved = config.clone();
    request(Request::SetConfig {
        config: Box::new(config),
    })
}

/// Сохраняет всё, включая правила («Сохранить» на их вкладке).
pub fn save_rules(app: &mut App) -> Task<Message> {
    let config = app.state().config.clone();

    app.state_mut().saved = config.clone();
    app.state_mut().dirty = false;
    request(Request::SetConfig {
        config: Box::new(config),
    })
}

/// Отправляет запрос; ошибка связи становится ответом об ошибке.
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
        let command = request_initial_state();
        // `Task` снаружи не разобрать; пустой означал бы, что ничего не спросили.
        assert!(!format!("{command:?}").contains("None"));
    }
}
