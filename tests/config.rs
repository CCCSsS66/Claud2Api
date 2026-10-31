use std::process::Command;

fn run(pairs: &[(&str, &str)]) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_claud2api"));
    command
        .env_clear()
        .env(
            "GATEWAY_API_KEY",
            "fixture-config-gateway-key-32-characters-only",
        )
        .env(
            "ADMIN_API_KEY",
            "fixture-config-admin-key-32-characters-only",
        );
    for (name, value) in pairs {
        command.env(name, value);
    }
    let output = command.output().unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn startup_rejects_unsafe_control_invalid_locale_and_missing_import() {
    for (name, value) in [
        ("CONTROL_BIND", "0.0.0.0:18082"),
        ("CLAUDE_LOCALE", "zh\r\nprivate-header: value"),
        ("CLAUDE_TIMEZONE", "Unknown/Timezone"),
        ("CLAUDE_COOKIE", "lastActiveOrg=fake-org"),
        (
            "STICKY_SESSION_STATE_FILE",
            "/missing-claud2api-import-fixture.json",
        ),
        ("ADMIN_ALLOW_CIDRS", "10.0.0.0/33"),
    ] {
        let (ok, error) = run(&[(name, value)]);
        assert!(!ok, "{name}={value} should be rejected");
        assert!(error.contains("startup_failed"));
        assert!(!error.contains("fixture-config"));
    }
}

#[test]
fn remote_control_requires_explicit_acknowledgement_and_transport() {
    let (ok, error) = run(&[
        ("CONTROL_BIND", "0.0.0.0:18082"),
        ("ALLOW_REMOTE_CONTROL", "true"),
    ]);
    assert!(!ok);
    assert!(error.contains("plaintext remote control"), "{error}");

    let (ok, error) = run(&[
        ("CONTROL_BIND", "0.0.0.0:18082"),
        ("ALLOW_REMOTE_CONTROL", "true"),
        ("TRUST_PROXY", "true"),
        ("CLAUD2API_DATA_DIR", "/proc/claud2api-unwritable"),
    ]);
    // Configuration validation passed; startup stops at the state directory.
    assert!(!ok);
    assert!(!error.contains("ALLOW_REMOTE_CONTROL"), "{error}");
    assert!(!error.contains("plaintext remote control"), "{error}");
    assert!(error.contains("startup_failed"), "{error}");
}

#[test]
fn tls_files_must_be_provided_as_a_pair() {
    let (ok, error) = run(&[("TLS_CERT_FILE", "/tmp/only-cert.pem")]);
    assert!(!ok);
    assert!(error.contains("TLS_KEY_FILE"), "{error}");
}

#[test]
fn control_tls_is_accepted_for_remote_exposure() {
    let (ok, error) = run(&[
        ("CONTROL_BIND", "0.0.0.0:18082"),
        ("ALLOW_REMOTE_CONTROL", "true"),
        ("CONTROL_TLS_CERT_FILE", "/missing-control-cert.pem"),
        ("CONTROL_TLS_KEY_FILE", "/missing-control-key.pem"),
    ]);
    assert!(!ok);
    assert!(error.contains("CONTROL_TLS_CERT_FILE"), "{error}");
    assert!(!error.contains("plaintext remote control"), "{error}");
}
