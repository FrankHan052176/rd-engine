extern crate base;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
use base::platform::linux;
#[cfg(target_os = "macos")]
use base::platform::macos;

fn main() {
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    let res = linux::system_message("test title", "test message", true);
    #[cfg(target_os = "macos")]
    let res = macos::alert(
        "System Preferences".to_owned(),
        "warning".to_owned(),
        "test title".to_owned(),
        "test message".to_owned(),
        ["Ok".to_owned()].to_vec(),
    );
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos"
    ))]
    println!("result {:?}", &res);
}
