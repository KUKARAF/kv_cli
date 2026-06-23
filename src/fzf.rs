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

    let mut child = cmd.spawn().context("failed to spawn fzf — is it installed?")?;

    {
        let stdin = child.stdin.as_mut().unwrap();
        for (i, item) in items.iter().enumerate() {
            writeln!(stdin, "{i}\t{item}")?;
        }
    }

    let output = child.wait_with_output()?;
    if output.stdout.is_empty() {
        bail!("no selection made");
    }

    let indices = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.split('\t').next()?.parse::<usize>().ok())
        .collect();

    Ok(indices)
}
