//! I2P — описание формы.
//!
//! Поле одно: адрес i2pd служба держит сама, а пустой outproxy — умолчание
//! протокола. Подпись говорит вслух, что outproxy видит трафик.

use crate::forms::protocol::spec::{FieldSpec, ProtocolSpec};

static FIELDS: &[FieldSpec] = &[
    FieldSpec::text("outproxy", &["outproxy"], |s| s.i2p_outproxy)
        .example(|s| s.i2p_outproxy_example),
];

/// Описание протокола.
pub static SPEC: ProtocolSpec = ProtocolSpec {
    id: "i2p",
    label: "I2P",
    fields: FIELDS,
    schemes: &[],
    from_link: None,
};
