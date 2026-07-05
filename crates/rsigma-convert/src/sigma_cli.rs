//! Optional delegation to an external `sigma-cli` for conversion targets that
//! rsigma has no native backend for.
//!
//! This is a light subprocess wrapper, not a port or an embedded interpreter:
//! callers hand the original rule files plus a near 1:1 flag mapping to
//! `sigma convert` and relay its output. No Python runtime is required unless
//! a delegated target is actually used, so rsigma binaries stay self-contained
//! for everyone converting to a native backend.
//!
//! The module is deliberately runtime-agnostic: [`build_convert_args`] and
//! [`classify_output`] are pure, and [`SigmaCli::run`] is a synchronous
//! convenience for CLI-style callers. An async caller (the MCP server) builds
//! its own `tokio::process::Command` from [`SigmaCli::program`] and the argv,
//! then classifies the captured [`Output`] through the same
//! [`classify_output`], so the two consumers cannot drift on flag mapping or
//! outcome handling.
//!
//! Discovery uses the `RSIGMA_SIGMA_CLI` environment override when set, falling
//! back to a bare `sigma` resolved on `PATH`. A spawn that fails with
//! [`std::io::ErrorKind::NotFound`] means sigma-cli is not installed, which the
//! caller turns into install guidance ([`install_hint`]) rather than a
//! conversion failure.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Environment variable that overrides discovery with an explicit path to the
/// `sigma` executable.
pub const SIGMA_CLI_ENV: &str = "RSIGMA_SIGMA_CLI";

/// Program name used when the override is unset.
const DEFAULT_PROGRAM: &str = "sigma";

/// A resolved sigma-cli invocation target.
pub struct SigmaCli {
    program: PathBuf,
    is_override: bool,
}

impl SigmaCli {
    /// Resolve the configured sigma-cli from the current environment.
    pub fn configured() -> Self {
        let (program, is_override) = resolve_program(std::env::var_os(SIGMA_CLI_ENV));
        Self {
            program,
            is_override,
        }
    }

    /// Build an invocation target from an explicit program path, bypassing
    /// environment discovery. Useful for tests that stub the executable
    /// without mutating process-global environment variables.
    pub fn from_program(program: impl Into<PathBuf>, is_override: bool) -> Self {
        Self {
            program: program.into(),
            is_override,
        }
    }

    /// The executable that will be spawned (override path or bare `sigma`).
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Whether the executable came from the `RSIGMA_SIGMA_CLI` override.
    pub fn is_override(&self) -> bool {
        self.is_override
    }

    /// Run sigma-cli with `args`, capturing stdout, stderr, and the exit
    /// status. Synchronous; async callers spawn their own command from
    /// [`Self::program`].
    pub fn run<I, S>(&self, args: I) -> std::io::Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new(&self.program).args(args).output()
    }
}

/// Decide the program name and whether it came from the override.
///
/// An override that is set but empty is treated as unset so an accidental
/// `RSIGMA_SIGMA_CLI=` does not break discovery.
fn resolve_program(env_value: Option<OsString>) -> (PathBuf, bool) {
    match env_value {
        Some(value) if !value.is_empty() => (PathBuf::from(value), true),
        _ => (PathBuf::from(DEFAULT_PROGRAM), false),
    }
}

/// A successfully classified delegated conversion.
#[derive(Debug)]
pub struct DelegatedConversion {
    /// Best-effort per-query split: each non-empty stdout line. Faithful for
    /// the line-oriented text backends; multi-line output formats should read
    /// [`Self::raw`] instead.
    pub queries: Vec<String>,
    /// The verbatim sigma-cli stdout (lossy UTF-8), the faithful copy of the
    /// conversion output regardless of format.
    pub raw: String,
    /// sigma-cli stderr on a zero exit: skipped-rule notes, deprecation
    /// warnings, and other diagnostics.
    pub stderr: String,
}

/// A failed delegated conversion.
#[derive(Debug)]
pub enum DelegateError {
    /// The sigma-cli executable could not be spawned because it does not
    /// exist. Callers surface [`install_hint`].
    NotInstalled {
        /// The executable that failed to spawn.
        program: PathBuf,
        /// Whether it came from the `RSIGMA_SIGMA_CLI` override.
        is_override: bool,
    },
    /// sigma-cli ran but exited non-zero.
    NonZero {
        /// The exit code, when the process was not killed by a signal.
        code: Option<i32>,
        /// Captured stdout (lossy UTF-8); usually empty on failure but
        /// preserved so callers can relay everything sigma-cli printed.
        stdout: String,
        /// Captured stderr (lossy UTF-8) carrying the error text.
        stderr: String,
    },
}

/// Classify a captured sigma-cli [`Output`] into a [`DelegatedConversion`] or
/// a [`DelegateError::NonZero`].
///
/// Spawn failures never reach this function; callers map a
/// [`std::io::ErrorKind::NotFound`] spawn error to
/// [`DelegateError::NotInstalled`] themselves because the raw
/// [`std::io::Error`] is only visible at the spawn site.
pub fn classify_output(output: &Output) -> Result<DelegatedConversion, DelegateError> {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(DelegateError::NonZero {
            code: output.status.code(),
            stdout,
            stderr,
        });
    }
    let queries = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect();
    Ok(DelegatedConversion {
        queries,
        raw: stdout,
        stderr,
    })
}

/// Build the `sigma convert` argument vector from rsigma's convert arguments.
///
/// The mapping is near 1:1; the only transform is rsigma's
/// `-O correlation_method=<m>` option, which becomes sigma-cli's
/// `-c/--correlation-method <m>`. Every other `-O key=value` is forwarded as a
/// sigma-cli `-O/--backend-option`, and pipelines, the no-pipeline and
/// skip-unsupported toggles, the output format, and the rule paths pass through
/// unchanged. `--output` is intentionally not forwarded: rsigma captures
/// sigma-cli's stdout and routes it through its own output handling.
pub fn build_convert_args(
    target: &str,
    format: &str,
    pipelines: &[PathBuf],
    without_pipeline: bool,
    skip_unsupported: bool,
    backend_options: &[String],
    rules: &[PathBuf],
) -> Vec<OsString> {
    fn os(value: impl AsRef<OsStr>) -> OsString {
        value.as_ref().to_os_string()
    }

    let mut argv: Vec<OsString> = vec![os("convert"), os("-t"), os(target), os("-f"), os(format)];

    for pipeline in pipelines {
        argv.push(os("-p"));
        argv.push(os(pipeline));
    }
    if without_pipeline {
        argv.push(os("--without-pipeline"));
    }
    if skip_unsupported {
        argv.push(os("-s"));
    }

    for option in backend_options {
        match option.split_once('=') {
            Some(("correlation_method", value)) => {
                argv.push(os("-c"));
                argv.push(os(value));
            }
            _ => {
                argv.push(os("-O"));
                argv.push(os(option));
            }
        }
    }

    for rule in rules {
        argv.push(os(rule));
    }

    argv
}

/// Message shown when a target has no native backend and sigma-cli cannot be
/// run, guiding the user to install it (or fix a broken override).
pub fn install_hint(
    target: &str,
    program: &Path,
    is_override: bool,
    native_targets: &[&str],
) -> String {
    let program = program.display();
    let native = native_targets.join(", ");
    if is_override {
        format!(
            "No native rsigma backend for target '{target}' (native targets: {native}), \
             and the sigma-cli override {SIGMA_CLI_ENV}='{program}' could not be executed.\n\
             Point {SIGMA_CLI_ENV} at a working sigma executable, or unset it to use one on PATH."
        )
    } else {
        format!(
            "No native rsigma backend for target '{target}' (native targets: {native}), \
             and sigma-cli was not found on PATH.\n\
             Install it to convert to '{target}':\n\
             \x20\x20pipx install sigma-cli\n\
             \x20\x20sigma plugin install {target}\n\
             Or set {SIGMA_CLI_ENV} to the path of an existing sigma executable."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn to_strings(argv: &[OsString]) -> Vec<String> {
        argv.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[cfg(unix)]
    fn exit_status(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(code as u32)
    }

    #[test]
    fn resolve_program_prefers_override() {
        let (program, is_override) = resolve_program(Some(OsString::from("/opt/sigma/bin/sigma")));
        assert_eq!(program, PathBuf::from("/opt/sigma/bin/sigma"));
        assert!(is_override);
    }

    #[test]
    fn resolve_program_falls_back_to_path() {
        let (program, is_override) = resolve_program(None);
        assert_eq!(program, PathBuf::from("sigma"));
        assert!(!is_override);
    }

    #[test]
    fn resolve_program_treats_empty_override_as_unset() {
        let (program, is_override) = resolve_program(Some(OsString::new()));
        assert_eq!(program, PathBuf::from("sigma"));
        assert!(!is_override);
    }

    #[test]
    fn from_program_bypasses_environment() {
        let cli = SigmaCli::from_program("/stub/sigma", true);
        assert_eq!(cli.program(), Path::new("/stub/sigma"));
        assert!(cli.is_override());
    }

    #[test]
    fn classify_output_splits_nonempty_lines_and_keeps_raw() {
        let output = Output {
            status: exit_status(0),
            stdout: b"query one\n\nquery two\n".to_vec(),
            stderr: b"warning: something\n".to_vec(),
        };
        let conv = classify_output(&output).expect("zero exit classifies as success");
        assert_eq!(conv.queries, vec!["query one", "query two"]);
        assert_eq!(conv.raw, "query one\n\nquery two\n");
        assert_eq!(conv.stderr, "warning: something\n");
    }

    #[test]
    fn classify_output_maps_nonzero_exit() {
        let output = Output {
            status: exit_status(1),
            stdout: b"partial\n".to_vec(),
            stderr: b"Error: bad pipeline\n".to_vec(),
        };
        match classify_output(&output) {
            Err(DelegateError::NonZero {
                code,
                stdout,
                stderr,
            }) => {
                assert_eq!(code, Some(1));
                assert_eq!(stdout, "partial\n");
                assert!(stderr.contains("bad pipeline"));
            }
            other => panic!("expected NonZero, got {other:?}"),
        }
    }

    #[test]
    fn build_args_maps_flags_one_to_one() {
        let argv = build_convert_args(
            "splunk",
            "default",
            &[PathBuf::from("ecs.yml"), PathBuf::from("custom.yml")],
            false,
            true,
            &["index=main".to_string()],
            &[PathBuf::from("rule.yml")],
        );
        assert_eq!(
            to_strings(&argv),
            vec![
                "convert",
                "-t",
                "splunk",
                "-f",
                "default",
                "-p",
                "ecs.yml",
                "-p",
                "custom.yml",
                "-s",
                "-O",
                "index=main",
                "rule.yml",
            ]
        );
    }

    #[test]
    fn build_args_special_cases_correlation_method() {
        let argv = build_convert_args(
            "loki",
            "default",
            &[],
            false,
            false,
            &["correlation_method=stats".to_string()],
            &[PathBuf::from("rule.yml")],
        );
        assert_eq!(
            to_strings(&argv),
            vec![
                "convert", "-t", "loki", "-f", "default", "-c", "stats", "rule.yml",
            ]
        );
    }

    #[test]
    fn build_args_adds_without_pipeline_flag() {
        let argv = build_convert_args(
            "loki",
            "ruler",
            &[],
            true,
            false,
            &[],
            &[PathBuf::from("a.yml"), PathBuf::from("b.yml")],
        );
        assert_eq!(
            to_strings(&argv),
            vec![
                "convert",
                "-t",
                "loki",
                "-f",
                "ruler",
                "--without-pipeline",
                "a.yml",
                "b.yml",
            ]
        );
    }

    #[test]
    fn install_hint_mentions_plugin_install_when_not_override() {
        let hint = install_hint("splunk", Path::new("sigma"), false, &["postgres", "lynxdb"]);
        assert!(hint.contains("sigma-cli was not found"));
        assert!(hint.contains("sigma plugin install splunk"));
        assert!(hint.contains("RSIGMA_SIGMA_CLI"));
        assert!(hint.contains("native targets: postgres, lynxdb"));
    }

    #[test]
    fn install_hint_mentions_override_path_when_override() {
        let hint = install_hint("splunk", Path::new("/bad/sigma"), true, &["postgres"]);
        assert!(hint.contains("/bad/sigma"));
        assert!(hint.contains("could not be executed"));
    }
}
