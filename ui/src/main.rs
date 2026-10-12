#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod actions;
mod api;
mod keys;
mod state;
mod views;

pub async fn sleep_ms(ms: u32) {
    #[cfg(target_arch = "wasm32")]
    {
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .expect("window")
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32)
                .expect("set_timeout");
        });
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = ms;
    }
}

fn main() {
    // `dx build --base-path .` gives Dioxus' default WebHistory a "/." prefix that never matches
    // /v1/contract/web/<key>/, so its startup replaceState rewrites the URL to "/" and drops
    // ?connect=… before we parse it. Prefix with the real path so that replaceState is a no-op.
    #[cfg(target_arch = "wasm32")]
    {
        let path = web_sys::window().and_then(|w| w.location().pathname().ok());
        let history = dioxus::web::WebHistory::new(path, true);
        dioxus::LaunchBuilder::new()
            .with_cfg(dioxus::web::Config::new().history(std::rc::Rc::new(history)))
            .launch(views::App);
    }
    #[cfg(not(target_arch = "wasm32"))]
    dioxus::launch(views::App);
}
