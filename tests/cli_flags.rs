// tests/cli_flags.rs
//
// Spawns the actual compiled binary (not a call into internal functions)
// specifically because the thing worth confirming here is that the
// compiled artifact itself responds the way an external invocation —
// Homebrew's `brew test` block, a user running `magus-gateway --version`
// by hand — actually expects, not just that some Rust function returns the
// right string.

use std::process::Command;

#[test]
fn version_flag_prints_version_and_exits_zero() {
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_magus-gateway"))
            .arg(flag)
            .output()
            .expect("failed to spawn the compiled magus-gateway binary");

        assert!(output.status.success(), "'{flag}' must exit 0, got: {:?}", output.status);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let expected = format!("magus-gateway {}", env!("CARGO_PKG_VERSION"));
        assert!(
            stdout.contains(&expected),
            "'{flag}' stdout must contain '{expected}', got: {stdout:?}"
        );
    }
}

#[test]
fn help_flag_prints_usage_and_exits_zero() {
    for flag in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_magus-gateway"))
            .arg(flag)
            .output()
            .expect("failed to spawn the compiled magus-gateway binary");

        assert!(output.status.success(), "'{flag}' must exit 0, got: {:?}", output.status);

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("magus-gateway"),
            "'{flag}' stdout must mention the binary name, got: {stdout:?}"
        );
        assert!(
            stdout.contains("Usage: magus-gateway [config.yaml]"),
            "'{flag}' stdout must contain the usage line, got: {stdout:?}"
        );
    }
}
