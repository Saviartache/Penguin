//! Границы монитора для анимации окна.

use iced::{Task, window};

use super::message::Message;

pub(super) fn moved(x: i32, y: i32) -> Task<Message> {
    // Не мешать перетаскиванию между мониторами.
    #[cfg(windows)]
    return Task::perform(
        async { tokio::time::sleep(std::time::Duration::from_millis(150)).await },
        move |()| Message::Window(super::message::WindowMessage::MoveSettled(x, y)),
    );
    #[cfg(not(windows))]
    {
        let _ = (x, y);
        Task::none()
    }
}

#[cfg(windows)]
pub(super) fn refresh(id: window::Id) -> Task<Message> {
    window::scale_factor(id)
        .then(move |scale| window::run(id, move |window| work_area(window, scale)))
        .map(|area| Message::Window(super::message::WindowMessage::WorkArea(area)))
}

#[cfg(windows)]
fn work_area(window: &dyn window::Window, scale: f32) -> Option<iced::Rectangle> {
    use iced::window::raw_window_handle::RawWindowHandle;

    let handle = match window.window_handle() {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(%error, "дескриптор окна недоступен");
            return None;
        }
    };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else {
        return None;
    };
    match penguin_platform::window::work_area(handle.hwnd.get()) {
        Ok((x, y, width, height)) => Some(iced::Rectangle {
            x: x as f32 / scale,
            y: y as f32 / scale,
            width: width as f32 / scale,
            height: height as f32 / scale,
        }),
        Err(error) => {
            tracing::warn!(%error, "рабочая область монитора недоступна");
            None
        }
    }
}

#[cfg(not(windows))]
pub(super) fn refresh(_id: window::Id) -> Task<Message> {
    Task::none()
}
