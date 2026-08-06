use anyhow::Result;

/// How to display a secret once retrieved/created. Set from a command's
/// `--return-md5-on-agent-true` / `--show-3-last-digits-on-agent-true` /
/// `--dangerously-show-content-on-agent-true` flags.
#[derive(Clone, Copy, Default)]
pub struct SecretDisplay {
    pub md5: bool,
    pub last3: bool,
    pub dangerously_show: bool,
}

/// Prints `value` (labeled `what`, e.g. "the key 'foo'" or "the new API key")
/// according to `mode`, unless it looks like an agent is invoking this
/// command directly (see `agent_detect`), in which case it prints a nudge to
/// stderr instead of the raw value. This is a UX nudge, not a security
/// control — see `agent_detect` for why it can't be one.
///
/// `retry_hint`, if given, is a command the user can safely re-run to see
/// the same value again (true for idempotent reads like `kv get`/`keys
/// show`). Pass `None` for one-shot actions (`keys create`/`rotate`) where
/// re-running would mint or invalidate a *different* key — the message
/// makes that distinction so the user doesn't think re-running is free.
pub fn emit_secret(
    what: &str,
    value: &str,
    mode: SecretDisplay,
    retry_hint: Option<&str>,
) -> Result<()> {
    if mode.dangerously_show || !crate::agent_detect::should_nudge() {
        print!("{value}");
        return Ok(());
    }

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

    eprintln!("success: {what}!");
    eprintln!();
    eprintln!("Its raw value isn't being printed here because this looks like an AI agent");
    eprintln!("running this command directly — printing it would put the secret into the");
    eprintln!("model's context and could leak it to the model provider. If you just want to");
    eprintln!("confirm the value without leaking it, use one of:");
    eprintln!();
    eprintln!("  --show-3-last-digits-on-agent-true");
    eprintln!("  --return-md5-on-agent-true");
    eprintln!();
    eprintln!("If this is a false positive, or you've built a safeguard elsewhere to make sure");
    eprintln!("the value won't reach the model (e.g. it's consumed entirely within a script),");
    eprintln!("force the raw value with:");
    eprintln!();
    eprintln!("  --dangerously-show-content-on-agent-true");
    eprintln!();
    match retry_hint {
        Some(hint) => {
            eprintln!("Re-running `{hint}` is safe and will show the same value again.");
            eprintln!();
            eprintln!("Note: using the value inside another command, e.g.");
            eprintln!("  curl -H \"Authorization: Bearer $({hint})\" https://example.com");
            eprintln!("does not trigger this message.");
        }
        None => {
            eprintln!("This action already happened server-side and can't be safely repeated —");
            eprintln!("re-running it would create/rotate a *different* key, not show you this one");
            eprintln!("again. If you didn't pass --dangerously-show-content-on-agent-true above,");
            eprintln!("the value is still stored encrypted and retrievable later via the");
            eprintln!("relevant `... show` subcommand.");
        }
    }
    anyhow::bail!("refusing to print secret directly to a detected agent invocation");
}
