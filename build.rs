fn main() {
    let version = std::env::var("VERSION").unwrap_or_else(|_| "dev".to_string());
    println!("cargo:rustc-env=APP_VERSION={version}");
    println!("cargo:rerun-if-env-changed=VERSION");
}
