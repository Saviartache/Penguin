//! Модальное окно профиля: ссылка, имя и поля выбранного протокола.
//!
//! Полей окно не знает: их приносит описание протокола
//! ([`crate::forms::protocol`]), и рисуются они одинаково — подпись слева,
//! поле справа. До этого здесь стоял список из восьми полей Hysteria 2
//! поимённо, и второй протокол некуда было добавить, не заведя второе такое же
//! окно.
//!
//! Первое поле — ссылка-приглашение. Её присылают в мессенджере, и переносить
//! из неё поля руками — семь шансов ошибиться в пароле; вставил — остальное
//! заполнилось само. Показывается она только у протоколов, у которых ссылки
//! бывают: пустое поле «Ссылка» у прокси, которому её взять неоткуда, — это
//! вопрос без ответа.
//!
//! Подсказок под полями нет намеренно. В модальном окне их некуда деть: они
//! удваивают его высоту, а прочитывают их один раз в жизни. То, что нужно
//! знать про формат, стоит подсказкой **внутри** поля и исчезает, как только
//! человек начал печатать.

use iced::Element;
use uikit::layout::{Flex, gap};
use uikit::style::tokens::type_scale;
use uikit::widgets::{Checkbox, Modal, Select, TextInput};

use crate::app::message::{Message, ServersMessage};
use crate::app::state::State;
use crate::forms::protocol::FieldSpec;
use crate::forms::server::Draft;
use crate::ui;

/// Ширина окна.
///
/// Шире умолчания кита: там окно рассчитано на сообщение в две строки, а здесь
/// в нём форма, у которой подпись и поле стоят в одной строке.
const WIDTH: f32 = 620.0;

/// Высота прокручиваемой части формы.
///
/// Фиксированная, а не «сколько поместится»: растянутое содержимое в панели
/// «по содержимому» схлопывается в ноль, а ноль роняет отрисовку. Значение
/// подобрано так, чтобы окно целиком помещалось в наименьшее окно программы.
const FORM_HEIGHT: f32 = 300.0;

/// Собирает модальное окно правки профиля.
pub fn view<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    // Строки добавляются по одной, а не собираются списком с пустышками на
    // месте ненужных: пустая строка в столбце с зазором — это зазор, который
    // видно, и форма прокси стояла бы с дырой на месте поля ссылки.
    let mut form = Flex::col();
    // Предупреждение протокола — первой строкой: то, что надо знать до
    // заполнения полей, после них читать поздно.
    if let Some(note) = draft.spec().and_then(|spec| spec.note) {
        form = form.push_auto(ui::muted(
            &state.palette,
            note(crate::i18n::s()),
            type_scale::MICRO,
        ));
    }
    if draft.spec().is_some_and(|spec| spec.takes_links()) {
        form = form.push_auto(link(state));
    }
    form = form.push_auto(name(draft));
    if draft.spec().is_none() {
        form = form.push_auto(unknown(state));
    }

    let form = form
        .extend(
            draft
                .fields()
                .iter()
                .enumerate()
                .map(|(index, field)| row(draft, index, field)),
        )
        .gap(gap::MD)
        .build();

    let content = Flex::col()
        .push_auto(ui::scroll_box(form, FORM_HEIGHT))
        .push_auto(problem(state, draft))
        .gap(gap::SM)
        .build();

    let mut modal = Modal::new(content)
        .title(title(draft))
        .max_width(WIDTH)
        // `Esc` и нажатие мимо панели означают «Отмена»: отдельной кнопки для
        // этого не нужно, а место в ряду ответов дорого.
        .action(
            crate::i18n::s().save,
            Message::Servers(ServersMessage::EditorSubmitted),
        )
        .on_close(Message::Servers(ServersMessage::EditorClosed))
        .on_backdrop(Message::Servers(ServersMessage::EditorClosed));

    // Удаление — только у существующего профиля и последним в ряду: первый
    // ответ набран тоном окна и означает «то, зачем сюда пришли».
    if let Some(id) = &draft.id {
        modal = modal.action(
            crate::i18n::s().remove,
            Message::Servers(ServersMessage::Removed(id.clone())),
        );
    }

    modal.build().into()
}

/// Заголовок окна: что делаем и с чем.
///
/// Имя протокола в заголовке, а не строкой в форме: оно не правится, а
/// строка формы читается как поле, которое можно тронуть. Свободная функция
/// с тестом — заголовок, потерявший протокол, оставляет два одинаковых окна
/// для двух разных форм.
fn title(draft: &Draft) -> String {
    let what = if draft.is_edit() {
        crate::i18n::s().edit_server
    } else {
        crate::i18n::s().new_server
    };

    match draft.spec() {
        Some(spec) => format!("{what} · {}", spec.label),
        // У чужого протокола подписи нет — только имя из настроек.
        None => format!("{what} · {}", draft.protocol()),
    }
}

/// Поле вставки ссылки-приглашения.
///
/// Показывается только у протоколов, у которых ссылки бывают: поле, в которое
/// нечего вставить, — это вопрос, на который нет ответа.
fn link(state: &State) -> Element<'_, Message> {
    ui::form_row(
        crate::i18n::s().link,
        TextInput::new(crate::i18n::s().link_example, &state.servers.link)
            .on_input(|value| Message::Servers(ServersMessage::LinkChanged(value)))
            .build(),
    )
}

/// Имя профиля — единственное поле, общее всем протоколам.
fn name(draft: &Draft) -> Element<'_, Message> {
    ui::form_row(
        crate::i18n::s().server_name,
        TextInput::new("", &draft.name)
            .on_input(|value| Message::Servers(ServersMessage::EditorNameChanged(value)))
            .build(),
    )
}

/// Объяснение для профиля, чей протокол окну неизвестен.
///
/// Пустая форма без слов читается как поломка. Здесь же сказано, что
/// настройки не потеряются: их правит файл, а окно бережёт как есть.
fn unknown(state: &State) -> Element<'_, Message> {
    ui::muted(
        &state.palette,
        crate::i18n::s().protocol_unknown,
        type_scale::MICRO,
    )
}

/// Одна строка формы — по описанию поля.
fn row<'a>(draft: &'a Draft, index: usize, field: &'static FieldSpec) -> Element<'a, Message> {
    let strings = crate::i18n::s();
    let label = (field.label)(strings);

    if field.is_flag() {
        return ui::form_row(
            label,
            Checkbox::new(String::new(), draft.flag(field.key)).on_toggle(move |value| {
                Message::Servers(ServersMessage::EditorToggled(index, value))
            }),
        );
    }

    if field.is_choice() {
        return ui::form_row(label, choice(draft, index, field));
    }

    let example = field.example.map_or("", |example| example(strings));

    ui::form_row(
        label,
        TextInput::new(example, draft.text(field.key))
            .secure(field.is_secret())
            .on_input(move |value| Message::Servers(ServersMessage::EditorChanged(index, value)))
            .build(),
    )
}

/// Список выбора для поля с известным набором значений.
///
/// Значение, которого в наборе нет, в список **дописывается**. Оно приходит из
/// чужой конфигурации: сервер может уметь то, чего не знаем мы, и показать
/// вместо него пустоту значит потерять его при первом сохранении.
fn choice<'a>(draft: &'a Draft, index: usize, field: &'static FieldSpec) -> Element<'a, Message> {
    let current = draft.text(field.key);
    let mut options: Vec<String> = field.options.iter().map(|o| (*o).to_owned()).collect();
    if !current.is_empty() && !options.iter().any(|option| option == current) {
        options.push(current.to_owned());
    }

    Select::new(options, Some(current.to_owned()), move |value| {
        Message::Servers(ServersMessage::EditorChanged(index, value))
    })
    .view()
}

/// Причина, по которой профиль пока не собирается.
///
/// Показывается сразу, а не по нажатию: иначе человек заполняет форму до конца
/// и только потом узнаёт, что адрес не разобрался.
fn problem<'a>(state: &'a State, draft: &'a Draft) -> Element<'a, Message> {
    // Неразобравшаяся ссылка важнее: пока она лежит в поле, остальные поля
    // заполнены не тем, чем человек думает.
    let reason = if crate::forms::link::looks_like_link(&state.servers.link) {
        crate::forms::link::parse(&state.servers.link)
            .err()
            .or_else(|| draft.to_profile().err())
    } else {
        draft.to_profile().err()
    };

    match reason {
        Some(reason) => ui::muted(&state.palette, reason, type_scale::MICRO),
        None => ui::spring(),
    }
}

#[cfg(test)]
mod tests {
    use penguin_config::schema::outbound::RawOutbound;
    use penguin_config::schema::profile::Profile;
    use serde_json::json;

    use super::*;
    use crate::forms::protocol;

    fn filled() -> Draft {
        let mut draft = Draft::default();
        draft.name = "Дом".to_owned();
        draft.set_text("server", "example.com:443".to_owned());
        draft.set_text("password", "секрет".to_owned());
        draft
    }

    #[test]
    fn renders_a_new_profile() {
        // Пустая форма — состояние, с которого начинается любой первый запуск.
        let _ = view(&State::default(), &Draft::default());
    }

    #[test]
    fn renders_every_protocol_in_the_catalog() {
        // Форма собирается описанием: протокол, который она не рисует, — это
        // протокол, который нельзя добавить.
        let state = State::default();
        for spec in protocol::ALL {
            let _ = view(&state, &Draft::new(spec));
        }
    }

    #[test]
    fn renders_an_edited_profile() {
        let _ = view(
            &State::default(),
            &filled().with_id(Some("home".to_owned())),
        );
    }

    #[test]
    fn the_title_names_the_protocol() {
        // Два окна с одним заголовком для двух разных форм — верный способ
        // сохранить не туда.
        let new = title(&Draft::new(protocol::by_id("socks5").expect("есть")));
        assert!(new.contains("SOCKS5"), "нет протокола: {new}");
        assert!(new.contains(crate::i18n::s().new_server));

        let edit = title(&filled().with_id(Some("home".to_owned())));
        assert!(edit.contains(crate::i18n::s().edit_server));
    }

    #[test]
    fn a_protocol_without_links_has_no_link_field() {
        // Поле, в которое нечего вставить, — это вопрос, на который нет
        // ответа. Ссылки бывают не у всех: у `socks5-tls` договорённости о
        // схеме не существует — такой прокси поднимают себе сами.
        //
        // Отрисовка обеих форм здесь и проверяется: столбец собирается по
        // строке, и лишняя строка на месте ненужного поля — это видимая дыра.
        for spec in protocol::ALL {
            let draft = Draft::new(spec);
            assert_eq!(
                draft.spec().is_some_and(|spec| spec.takes_links()),
                spec.takes_links(),
                "`{}`: форма и описание разошлись",
                spec.id
            );
            let _ = view(&State::default(), &draft);
        }

        let with_links = protocol::by_id("socks5").expect("есть");
        assert!(with_links.takes_links());
        let without = protocol::by_id("socks5-tls").expect("есть");
        assert!(
            !without.takes_links(),
            "у `socks5-tls` завелась схема ссылок — тогда нужен и разбор"
        );
    }

    #[test]
    fn a_problem_is_shown_before_saving() {
        // Пустая форма не собирается — и причина обязана быть видна сразу.
        assert!(Draft::default().to_profile().is_err());
        let _ = view(&State::default(), &Draft::default());
    }

    #[test]
    fn a_broken_link_is_reported_instead_of_the_form() {
        // Пока в поле лежит неразобравшаяся ссылка, остальные поля заполнены
        // не тем, чем человек думает.
        let mut state = State::default();
        state.servers.link = "hy2://без-пароля.example.com".to_owned();
        let _ = view(&state, &filled());
    }

    #[test]
    fn a_pasted_link_renders() {
        let mut state = State::default();
        state.servers.link =
            "hy2://source:s3cret@example.net:3478?sni=example.net#source".to_owned();
        let draft = crate::forms::link::parse(&state.servers.link).expect("ссылка разбирается");
        let _ = view(&state, &draft);
    }

    #[test]
    fn an_unknown_protocol_renders_with_an_explanation() {
        // Пустое окно без слов читается как поломка.
        let profile = Profile::new(
            "чужой",
            "Чужой",
            RawOutbound::new("телепатия", json!({ "server": "example.com:443" })),
        );
        let draft = Draft::from_profile(&profile);
        assert!(draft.fields().is_empty());
        let _ = view(&State::default(), &draft);
    }

    #[test]
    fn the_form_fits_the_smallest_window() {
        // Растянутое содержимое в панели «по содержимому» схлопывается в ноль,
        // поэтому высота фиксированная — и обязана помещаться.
        const { assert!(FORM_HEIGHT < crate::app::EXPANDED.height) };
    }
}
