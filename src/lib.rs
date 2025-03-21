pub mod app;
pub mod components;
pub mod consts;
pub mod context;
pub mod error;
#[cfg(feature = "ssr")]
pub mod kv;
pub mod oauth;
mod page;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;

    // initializes logging using the `log` crate
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    leptos::mount::hydrate_body(App);
}
