use leptos::prelude::{expect_context, provide_context};

use crate::oauth::client::ClientIdValidatorImpl;

#[cfg(feature = "ssr")]
pub mod server;

pub fn provide_client_id_validator() {
    provide_context(ClientIdValidatorImpl::Const(Default::default()));
}

pub fn client_id_validator() -> ClientIdValidatorImpl {
    expect_context::<ClientIdValidatorImpl>()
}
