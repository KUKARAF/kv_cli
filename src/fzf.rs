use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};

/// Pipe `items` into fzf and return the indices of selected entries.
/// The index is hidden from the user via `--with-nth 2..` so they only see
/// the display text.  Multi-select is enabled when `multi` is true.
pub fn select(items: &[String], multi: bool, prompt: &str) -> Result<Vec<usize>> {
    let mut cmd = Command::new("fzf");
    if multi {
        cmd.arg("--multi");
    }
    cmd.args(["--prompt", prompt, "--with-nth", "2..", "--delimiter", "\t"]);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context("failed to spawn fzf — is it installed?")?;

    {
        // We just configured stdin as `Stdio::piped()` above, so `child.stdin`
        // is guaranteed to be `Some` here; still propagate an error instead of
        // panicking in case that invariant is ever broken by a future refactor.
        let stdin = child
            .stdin
            .as_mut()
            .context("fzf child process has no stdin pipe")?;
        for (i, item) in items.iter().enumerate() {
            writeln!(stdin, "{i}\t{item}")?;
        }
    }

    let output = child.wait_with_output()?;
    if output.stdout.is_empty() {
        bail!("no selection made");
    }

    let indices: Vec<usize> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.split('\t').next()?.parse::<usize>().ok())
        .collect();

    if indices.is_empty() {
        bail!("no selection made");
    }
    if let Some(&bad) = indices.iter().find(|&&i| i >= items.len()) {
        bail!("fzf returned out-of-range selection index {bad}");
    }

    Ok(indices)
}
