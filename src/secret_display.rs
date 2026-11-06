use anyhow::Result;
use std::io::Write;

/// Optional non-secret representations of a secret, set from a command's
/// `--return-md5-on-agent-true` / `--show-3-last-digits-on-agent-true` flags. With
/// neither set, the raw value is printed.
#[derive(Clone, Copy, Default)]
pub struct SecretDisplay {
    pub md5: bool,
    pub last3: bool,
}

/// Prints `value` according to `mode`. The raw value goes to stdout with no prompt,
/// no terminal check and no trailing newline, so it can be captured directly:
/// `curl -H "Authorization: Bearer $(kv get KEY)" …`.
pub fn emit_secret(_what: &str, value: &str, mode: SecretDisplay) -> Result<()> {
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

    print!("{value}");
    // Best-effort flush so the value is emitted before we return; a failure here
    // is not worth aborting over (stdout is flushed again on process exit).
    std::io::stdout().flush().ok();
    Ok(())
}
