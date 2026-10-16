//! The remote half of the bootstrap: a POSIX `sh` script, run through the login shell by ssh, that
//! finds or receives the relay, checks it, and execs it. Also the parser for the status lines it
//! prints.
//!
//! The script is one line with no `'`, `!` or `\`, so wrapped in single quotes it reaches `sh`
//! intact through any login shell: csh rejects newlines inside quotes and history-expands `!`, and
//! fish treats `\` specially even inside single quotes.

use std::fmt::Write as _;

use anyhow::{anyhow, bail};

use crate::{arch::Arch, base::Res, relays::Relays};

/// Every status line starts with this; anything else on stdout (an rc file's echo) is noise.
pub const PREFIX: &str = "@@beachhead:";

/// The script, one statement per line so it can be read and annotated. Comment lines are dropped
/// and the rest joined with spaces, so every line ends where a space may follow: after `;`, `do`,
/// `then` or `{`.
const TEMPLATE: &str = r#"
# End any partial line an rc file left on stdout, so every status line starts a line of its own.
echo;
# Pick this arch's relay: S is its sha256, N its size.
P=@@beachhead:;
case $(uname -m) in @ARMS@ *) echo "${P}ERR unsupported arch $(uname -m)"; exit 1;; esac;
u=$(id -u);
# Candidate dirs, best first. The ${X:+"..."} form adds the runtime dir only when it is set.
set -- "${XDG_CACHE_HOME:-$HOME/.cache}/beachhead" ${XDG_RUNTIME_DIR:+"$XDG_RUNTIME_DIR/beachhead"} "/dev/shm/beachhead-$u" "${TMPDIR:-/tmp}/beachhead-$u";
# Usable means a real directory this user owns: in a shared tmpfs, another user could plant one.
safe() { [ -L "$1" ] && return 1; mkdir -p "$1" 2>/dev/null; chmod 700 "$1" 2>/dev/null && [ -O "$1" ]; };
# The right size, then the right sha256 when sha256sum exists.
sum() { [ "$(($(wc -c < "$1")))" = "$N" ] || return 1; command -v sha256sum >/dev/null 2>&1 || return 0; set -- $(sha256sum "$1"); [ "$1" = "$S" ]; };
# A cache hit needs the right bytes and a probe that proves the mount still allows exec.
for d do f=$d/relay-$S; [ -x "$f" ] && sum "$f" && "$f" --probe >/dev/null 2>&1 && { echo "${P}READY $S $d"; exec "$f" --stdio; }; done;
# A miss: find a staging file first, so a failure is reported before the client sends anything.
t=; for d do safe "$d" && : > "$d/.relay-$S.$$" 2>/dev/null && { t=$d/.relay-$S.$$; break; }; done;
[ -n "$t" ] || { echo "${P}ERR no writable cache directory"; exit 1; };
echo "${P}SEND $S $N";
head -c "$N" > "$t" && sum "$t" || { rm -f "$t"; echo "${P}ERR the relay arrived corrupted"; exit 1; };
chmod 700 "$t";
# Install into the first dir whose mount allows exec. mv is atomic, so concurrent runs are safe.
for d do safe "$d" || continue; s=$d/.relay-$S.$$; [ "$s" = "$t" ] || cp "$t" "$s" 2>/dev/null || continue; chmod 700 "$s"; if "$s" --probe >/dev/null 2>&1; then [ "$s" = "$t" ] || rm -f "$t"; mv -f "$s" "$d/relay-$S" && s=$d/relay-$S; echo "${P}READY $S $d"; exec "$s" --stdio; fi; [ "$s" = "$t" ] || rm -f "$s"; done;
# Every mount is noexec: run from an anonymous memfd instead, uncached. Flags 0 (no MFD_CLOEXEC)
# so a relay that is a #! script runs too; the fd the relay inherits is harmless.
command -v python3 >/dev/null 2>&1 && { echo "${P}READY $S memfd"; exec python3 -c "import os,sys;s=os.open(sys.argv[1],os.O_RDONLY);m=os.memfd_create(sys.argv[2],0);os.sendfile(m,s,0,os.fstat(s).st_size);os.unlink(sys.argv[1]);os.execve(m,sys.argv[2:],os.environ)" "$t" beachhead-relay --stdio; };
rm -f "$t"; echo "${P}ERR every directory is noexec and python3 is missing for the memfd fallback"; exit 1
"#;

/// The bootstrap script for `relays`, as one line.
#[must_use]
pub fn script(relays: &Relays) -> String {
    let mut arms = String::new();
    for arch in Arch::ALL {
        let pattern = arch.unames().join("|");
        // Writing to a String can't fail.
        let _ = match relays.get(arch) {
            Some(relay) => write!(arms, "{pattern}) S={}; N={};;", relay.sha256(), relay.len()),
            None => write!(arms, r#"{pattern}) echo "${{P}}ERR no {arch} relay in this beachhead build"; exit 1;;"#),
        };
        arms.push(' ');
    }
    let script: Vec<&str> = TEMPLATE.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')).collect();
    script.join(" ").replace("@ARMS@ ", &arms)
}

/// The command ssh runs through the remote login shell.
#[must_use]
pub fn remote_command(relays: &Relays) -> String {
    format!("sh -c '{}'", script(relays))
}

/// A status line from the script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line<'a> {
    /// No usable cached relay: send exactly `len` bytes of the relay with this sha256.
    Send { sha256: &'a str, len: usize },
    /// The relay is about to exec from `dir` (`memfd` for the uncached fallback); its `Hello`
    /// follows.
    Ready { sha256: &'a str, dir: &'a str },
    /// The bootstrap gave up.
    Err(&'a str),
}

/// Parses one stdout line, or returns `None` for a line without the [`PREFIX`].
#[must_use]
pub fn parse_line(raw: &[u8]) -> Option<Res<Line<'_>>> {
    let rest = raw.strip_prefix(PREFIX.as_bytes())?;
    Some(parse_status(rest))
}

fn parse_status(rest: &[u8]) -> Res<Line<'_>> {
    let rest = std::str::from_utf8(rest).map_err(|e| anyhow!("status line is not UTF-8: {e}"))?.trim_end_matches(['\r', '\n']);
    let (verb, args) = rest.split_once(' ').unwrap_or((rest, ""));
    Ok(match verb {
        "SEND" => {
            let Some((sha256, len)) = args.split_once(' ') else { bail!("malformed SEND: `{rest}`") };
            Line::Send {
                sha256,
                len: len.parse().map_err(|e| anyhow!("malformed SEND length `{len}`: {e}"))?,
            }
        }
        "READY" => {
            let Some((sha256, dir)) = args.split_once(' ') else { bail!("malformed READY: `{rest}`") };
            Line::Ready { sha256, dir }
        }
        "ERR" => Line::Err(args),
        other => bail!("unknown status `{other}`"),
    })
}

#[cfg(test)]
mod unit {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::relays::{Relay, Source};

    fn both() -> Relays {
        let x86 = Relay::new(Arch::X86_64, Bytes::from_static(b"x86 relay"));
        let arm = Relay::new(Arch::Aarch64, Bytes::from_static(b"arm relay!"));
        Relays::new(vec![x86, arm], Source::Embedded).unwrap()
    }

    #[test]
    fn script_is_one_line_with_nothing_a_login_shell_would_mangle() {
        let script = script(&both());
        for bad in ['\n', '\r', '\'', '!', '\\'] {
            assert!(!script.contains(bad), "the script contains {bad:?}");
        }
    }

    #[test]
    fn script_bakes_in_each_relays_sha256_and_size() {
        let relays = both();
        let script = script(&relays);
        for relay in relays.iter() {
            assert!(script.contains(&format!("S={}; N={};;", relay.sha256(), relay.len())), "{} missing", relay.arch());
        }
        assert!(!script.contains("@ARMS@"));
    }

    #[test]
    fn an_absent_arch_gets_an_error_arm() {
        let x86 = Relay::new(Arch::X86_64, Bytes::from_static(b"x86 relay"));
        let script = script(&Relays::new(vec![x86], Source::Embedded).unwrap());
        assert!(script.contains(r#"aarch64|arm64) echo "${P}ERR no aarch64 relay"#), "{script}");
    }

    #[test]
    fn remote_command_single_quotes_the_script() {
        let command = remote_command(&both());
        assert!(command.starts_with("sh -c '") && command.ends_with('\''));
        assert_eq!(command.matches('\'').count(), 2);
    }

    #[test]
    fn lines_without_the_prefix_are_noise() {
        assert!(parse_line(b"Welcome to the server!\n").is_none());
        assert!(parse_line(b" @@beachhead:READY x y\n").is_none());
    }

    #[test]
    fn status_lines_parse() {
        assert_eq!(parse_line(b"@@beachhead:SEND abc 123\n").unwrap().unwrap(), Line::Send { sha256: "abc", len: 123 });
        assert_eq!(
            parse_line(b"@@beachhead:READY abc /home/a b/.cache/beachhead\r\n").unwrap().unwrap(),
            Line::Ready {
                sha256: "abc",
                dir: "/home/a b/.cache/beachhead"
            }
        );
        assert_eq!(parse_line(b"@@beachhead:ERR no writable cache directory\n").unwrap().unwrap(), Line::Err("no writable cache directory"));
    }

    #[test]
    fn malformed_status_lines_are_errors() {
        for raw in [
            &b"@@beachhead:SEND abc\n"[..],
            b"@@beachhead:SEND abc lots\n",
            b"@@beachhead:READY abc\n",
            b"@@beachhead:HELLO\n",
            b"@@beachhead:\xff\n",
        ] {
            assert!(parse_line(raw).unwrap().is_err(), "{}", String::from_utf8_lossy(raw));
        }
    }
}
