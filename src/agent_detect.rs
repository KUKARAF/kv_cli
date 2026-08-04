//! Best-effort heuristics for "am I being invoked directly by an AI coding
//! agent's shell-tool harness right now" — used to nudge `kv get` away from
//! printing secrets straight into a model's context. This is NOT a security
//! boundary: every signal here is an environment variable or a parent
//! process's command line, both of which a determined caller can spoof or
//! suppress. It only has to be good enough to avoid firing on legitimate
//! script usage (e.g. `curl -H "Authorization: Bearer $(kv get KEY)"`).

use std::env;

/// Environment variables reported (with varying confidence) to be set by
/// AI coding agent harnesses when they spawn shell commands. Only
/// `CLAUDECODE` / `CLAUDE_CODE_CHILD_SESSION` are verified against Claude
/// Code's own docs; the rest are community-reported and may drift or never
/// have been accurate — false positives here just mean an unnecessary nudge,
/// so we err on the side of including them.
const AGENT_ENV_MARKERS: &[&str] = &[
    "CLAUDE_CODE_CHILD_SESSION",
    "CLAUDECODE",
    "OPENCODE_CLIENT",
    "CURSOR_AGENT",
    "CLINE_ACTIVE",
    "GEMINI_CLI",
    "CODEX_SANDBOX",
    "AGENT",
];

fn is_agent_environment() -> bool {
    AGENT_ENV_MARKERS.iter().any(|k| env::var_os(k).is_some())
}

/// Shell metacharacters that indicate `kv get` is one part of a larger
/// pipeline/substitution rather than the entire command line.
const SHELL_METACHARACTERS: &[&str] = &["$(", "`", "|", "&&", ";", ">", "<", "&"];

#[cfg(target_os = "linux")]
fn parent_cmdline() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let ppid: u32 = status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|rest| rest.trim().parse().ok())?;
    let raw = std::fs::read(format!("/proc/{ppid}/cmdline")).ok()?;
    let joined = raw
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

#[cfg(not(target_os = "linux"))]
fn parent_cmdline() -> Option<String> {
    None
}

/// Claude Code's Bash tool wraps every command it runs — bare or not — in a
/// snapshot-loading/cwd-tracking preamble and suffix of its own, e.g.:
/// `bash -c "source <snapshot>.sh || true && shopt -u extglob || true &&
/// eval '<command>' < /dev/null && pwd -P >| <tmpfile>"`. That wrapper's own
/// `&&`/`eval` syntax would otherwise swamp the metacharacter check below for
/// *every* invocation. When this shape is detected, pull out just `<command>`
/// and check that instead. This is tied to Claude Code's current
/// (undocumented) wrapper format and will simply stop matching — falling
/// back to checking the whole cmdline, same as any unrecognized wrapper — if
/// that format changes.
fn unwrap_claude_code_bash_tool(cmdline: &str) -> Option<&str> {
    const SUFFIX_MARKER: &str = " < /dev/null && pwd -P";
    const EVAL_MARKER: &str = "&& eval ";

    let end = cmdline.find(SUFFIX_MARKER)?;
    let prefix = cmdline.get(..end)?;
    let start = prefix.rfind(EVAL_MARKER)? + EVAL_MARKER.len();
    let inner = prefix.get(start..)?.trim();
    Some(
        inner
            .strip_prefix('\'')
            .and_then(|s| s.strip_suffix('\''))
            .unwrap_or(inner),
    )
}

/// True when `kv get` looks like the *entire* command the shell was asked to
/// run, rather than a sub-expression feeding another program (e.g. embedded
/// in `$(...)` for a `curl` header). Defaults to `false` (no nudge) whenever
/// the parent's command line can't be read — including on any non-Linux
/// target — since a missed nudge is far less disruptive than a false-fire on
/// legitimate script usage.
fn is_bare_invocation() -> bool {
    match parent_cmdline() {
        Some(cmdline) => {
            let command = unwrap_claude_code_bash_tool(&cmdline).unwrap_or(cmdline.as_str());
            !SHELL_METACHARACTERS.iter().any(|m| command.contains(m))
        }
        None => false,
    }
}

/// Whether `kv get` should nudge instead of printing the raw secret.
pub fn should_nudge() -> bool {
    is_agent_environment() && is_bare_invocation()
}
