//! The symbols of the `x25519-cortex-m` assembly carry the semver-compatible crate version.

#[test]
fn symbols_carry_the_version() {
    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let version = match major {
        "0" => format!("0_{}", env!("CARGO_PKG_VERSION_MINOR")),
        _ => major.to_owned(),
    };
    let prefix = format!("xwing_embedded_{version}_");
    for source in [
        include_str!("../vendor/x25519-cortex-m4/x25519-cortex-m4-gcc.s"),
        include_str!("../src/cortex_m.rs"),
    ] {
        assert!(source.contains(&format!("{prefix}curve25519_scalarmult")));
        assert_eq!(
            source.matches("xwing_embedded_").count(),
            source.matches(&prefix).count()
        );
    }
}
