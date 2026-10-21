fn main() {
    embuild::espidf::sysenv::output();
    // esp-idf-sys sets the target chip as a cfg (`esp32s3`, `esp32c5`); the
    // firmware switches pins and its update channel on it.
    println!("cargo:rustc-check-cfg=cfg(esp32s3, esp32c5)");
}
