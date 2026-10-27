fn main() {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("ohos") {
        panic!("rustdesk-ohrs is the HarmonyOS-only kernel output; use native/frb on other platforms");
    }
    napi_build_ohos::setup();
}
