use anyhow::{Context, Result};
use std::io::{IsTerminal, Write};

/// How to represent a secret when the caller only wants to *confirm* it without
/// exposing the raw value. Set from a command's `--return-md5-on-agent-true` /
/// `--show-3-last-digits-on-agent-true` flags. These "safe" representations are
/// derived, non-reversible fingerprints — not the secret itself — so they may be
/// produced non-interactively. When neither is set, the raw value is only ever
/// printed after a genuine interactive human confirmation (see [`emit_secret`]).
#[derive(Clone, Copy, Default)]
pub struct SecretDisplay {
    pub md5: bool,
    pub last3: bool,
}

/// Prints `value` (a plaintext secret, labeled `what`) according to `mode`.
///
/// Security model — this deliberately does NOT use any "is this an agent?"
/// heuristic (environment variables, parent process inspection, etc.): those
/// fail exactly when it matters (a bash-tool-driven, non-interactive invocation
/// is trivially misclassified as "human"), so relying on them silently leaks
/// secrets. Instead the gate is genuine interactivity:
///
/// * `--return-md5-on-agent-true` / `--show-3-last-digits-on-agent-true` emit a
///   non-secret fingerprint and are always allowed, interactive or not.
/// * Otherwise the RAW secret is revealed only when BOTH stdin and stdout are a
///   real terminal AND the operator types an explicit confirmation. A
///   non-interactive or agent invocation — a pipe, a redirect, or any captured
///   stdout — can never obtain the raw value. There is no override flag.
pub fn emit_secret(what: &str, value: &str, mode: SecretDisplay) -> Result<()> {
    if mode.md5 {
        use md5::{Digest, Md5};
        let hash = Md5::digest(value.as_bytes());
        println!("{hash:x}");
        return Ok(());
    }

    if mode.last3 {
        let tail: String = {
            let mut chars: Vec<char> = value.chars().rev().take(3).collect();
            chars.reverse();
            chars.into_iter().collect()
        };
        println!("...{tail}");
        return Ok(());
    }

    confirm_interactive_reveal(what)?;
    print!("{value}");
    // Best-effort flush so the value is emitted before we return; a failure here
    // is not worth aborting over (stdout is flushed again on process exit).
    std::io::stdout().flush().ok();
    Ok(())
}

/// Enforces that a raw-secret reveal is driven by a genuine interactive human.
/// Errors out unless BOTH stdin and stdout are a TTY, then requires the operator
/// to type `yes`. A non-interactive/agent invocation cannot satisfy either
/// condition, and there is intentionally no flag to bypass it.
fn confirm_interactive_reveal(what: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "refusing to print a raw secret ({what}) to a non-interactive session: stdin and \
             stdout must both be an interactive terminal so a human can confirm the reveal. \
             There is no flag to override this. For a safe, non-secret fingerprint that works \
             non-interactively, re-run with --show-3-last-digits-on-agent-true or \
             --return-md5-on-agent-true."
        );
    }

    eprintln!();
    eprintln!("About to print a RAW SECRET to this terminal: {what}.");
    eprintln!("This exposes the plaintext on screen. Only continue at a trusted terminal.");
    eprint!("Type 'yes' to reveal, anything else to abort: ");
    std::io::stderr().flush().ok();

    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("failed to read confirmation from the terminal")?;
    if answer.trim() != "yes" {
        anyhow::bail!("aborted: the raw secret was not printed");
    }
    eprintln!();
    Ok(())
}
