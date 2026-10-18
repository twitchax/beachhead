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
pub const PREFIX: &str = "@@sshunnel:";

/// The script, one statement per line so it can be read and annotated. Comment lines are dropped
/// and the rest joined with spaces, so every line ends where a space may follow: after `;`, `do`,
/// `then` or `{`.
const TEMPLATE: &str = r#"
# End any partial line an rc file left on stdout, so every status line starts a line of its own.
echo;
# Pick this arch's relay: S is its sha256, N its size.
P=@@sshunnel:;
case $(uname -m) in @ARMS@ *) echo "${P}ERR unsupported arch $(uname -m)"; exit 1;; esac;
u=$(id -u);
# Candidate dirs, best first. The ${X:+"..."} form adds the runtime dir only when it is set.
set -- "${XDG_CACHE_HOME:-$HOME/.cache}/sshunnel" ${XDG_RUNTIME_DIR:+"$XDG_RUNTIME_DIR/sshunnel"} "/dev/shm/sshunnel-$u" "${TMPDIR:-/tmp}/sshunnel-$u";
# H is the first sha256 hasher on PATH, or empty. Each prints the hex digest as its first word.
H=; for h in sha256sum "shasum -a 256" "openssl dgst -sha256 -r"; do command -v ${h%% *} >/dev/null 2>&1 && { H=$h; break; }; done;
# mine PATH PATTERN: the ls -l mode of PATH matches PATTERN and this user owns it. ls -ld lists the
# entry itself (an lstat), so a symlink shows as l... and never passes for a dir or a file.
mine() { set -- "$2" $(ls -ldn "$1" 2>/dev/null); case $2 in $1) [ "$4" = "$u" ];; *) false;; esac; };
# Private means a real directory this user owns that no one else may write to: in a shared tmpfs,
# another user could plant one. Once it is ours, the sticky bit keeps anyone else from replacing it.
private() { mine "$1" "d????-??-*"; };
# A dir to write into: created private when missing. One this user owns but others may write to is
# made private first, and only after the owner check.
usable() { mkdir -p -m 700 "$1" 2>/dev/null; private "$1" || { mine "$1" "d*" && chmod 700 "$1"; }; };
# The right size, then the right sha256 when there is a hasher.
sum() { [ "$(($(wc -c < "$1")))" = "$N" ] || return 1; [ -n "$H" ] || return 0; set -- $($H < "$1"); [ "$1" = "$S" ]; };
# A received relay passes sum, unless the hasher is what is broken: one that gets the sha256 of
# nothing wrong is dropped, and the relay is checked by size alone (ssh protects the bytes in
# transit). Without a hasher there are no hits, so such a box gets a push every run.
ok() { sum "$1" && return; r=$1; [ -n "$H" ] && set -- $(: | $H) && [ "$1" = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ] && return 1; H=; sum "$r"; };
# A fresh, empty staging file in $1, its path on stdout: from mktemp where there is one, else named
# for this shell's pid (which can collide across hosts sharing an NFS home). The fallback uses true,
# not the special builtin :, whose failed redirection would end the shell.
stage() { mktemp "$1/.relay-$S.XXXXXX" 2>/dev/null || { true > "$1/.relay-$S.$$" && echo "$1/.relay-$S.$$"; } 2>/dev/null; };
# Relays installed over 30 days ago belong to old builds: clear them out as a new one goes in. One
# still in use elsewhere is pushed again, once; in exchange, a hit costs nothing extra.
evict() { find "$1" -name "relay-*" -mtime +30 -exec rm -f {} ";" 2>/dev/null; };
# A cache hit needs a private dir, a regular file this user owns, a real sha256 and a probe that
# proves the mount still allows exec; the [ -f ] spares all that for a dir with no copy. With no
# hasher there are no hits, and the client sends the relay instead. Every probe reads /dev/null:
# the session is the client's, and the client is waiting.
[ -n "$H" ] && for d do f=$d/relay-$S; [ -f "$f" ] && private "$d" && mine "$f" "-*" && [ -x "$f" ] && sum "$f" && "$f" --probe </dev/null >/dev/null 2>&1 && { echo "${P}READY $S $d"; exec "$f" --stdio; }; done;
# A miss: receive the relay into the first dir that can hold it. Each try sends SEND only once its
# staging file exists, so a dir that can't take one costs no transfer. A write that fails (a full
# disk, a quota) still drains its copy, which keeps the session in step for the next try.
t=; e="no writable cache directory this user owns"; for d do usable "$d" && s=$(stage "$d") || continue; echo "${P}SEND $S $N"; if head -c "$N" | { cat > "$s" 2>/dev/null || { cat > /dev/null; false; }; }; then ok "$s" && { t=$s; break; }; rm -f "$s"; echo "${P}ERR the relay arrived corrupted"; exit 1; fi; rm -f "$s"; e="no cache directory had room for the relay"; done;
[ -n "$t" ] || { echo "${P}ERR $e"; exit 1; };
# Install into the first dir whose mount allows exec; the dir holding the staged copy already
# passed. mv is atomic, so concurrent runs are safe.
for d do if [ "${t%/*}" = "$d" ]; then s=$t; else usable "$d" && s=$(stage "$d") || continue; cp "$t" "$s" 2>/dev/null || { rm -f "$s"; continue; }; fi; chmod 700 "$s"; if "$s" --probe </dev/null >/dev/null 2>&1; then [ "$s" = "$t" ] || rm -f "$t"; mv -f "$s" "$d/relay-$S" && s=$d/relay-$S; evict "$d"; echo "${P}READY $S $d"; exec "$s" --stdio; fi; [ "$s" = "$t" ] || rm -f "$s"; done;
# Every mount is noexec: run from an anonymous memfd instead, uncached. Python unlinks the staged
# file before anything can fail, so a python without memfd_create (older than 3.8, or behind
# seccomp) leaves nothing behind. F is MFD_EXEC wherever vm.memfd_noexec exists (Linux 6.3+): at 1
# it seals any memfd made without it noexec, and older kernels reject the flag. No MFD_CLOEXEC, so a
# relay that is a #! script runs too; the fd the relay inherits is harmless.
F=0; [ -e /proc/sys/vm/memfd_noexec ] && F=16;
command -v python3 >/dev/null 2>&1 && { echo "${P}READY $S memfd"; exec python3 -c "import os,sys;s=os.open(sys.argv[1],os.O_RDONLY);os.unlink(sys.argv[1]);m=os.memfd_create(sys.argv[3],int(sys.argv[2]));os.sendfile(m,s,0,os.fstat(s).st_size);os.execve(m,sys.argv[3:],os.environ)" "$t" "$F" sshunnel-relay --stdio; };
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
            None => write!(arms, r#"{pattern}) echo "${{P}}ERR no {arch} relay in this sshunnel build"; exit 1;;"#),
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
        assert!(parse_line(b" @@sshunnel:READY x y\n").is_none());
    }

    #[test]
    fn status_lines_parse() {
        assert_eq!(parse_line(b"@@sshunnel:SEND abc 123\n").unwrap().unwrap(), Line::Send { sha256: "abc", len: 123 });
        assert_eq!(
            parse_line(b"@@sshunnel:READY abc /home/a b/.cache/sshunnel\r\n").unwrap().unwrap(),
            Line::Ready {
                sha256: "abc",
                dir: "/home/a b/.cache/sshunnel"
            }
        );
        assert_eq!(parse_line(b"@@sshunnel:ERR no writable cache directory\n").unwrap().unwrap(), Line::Err("no writable cache directory"));
    }

    #[test]
    fn malformed_status_lines_are_errors() {
        for raw in [
            &b"@@sshunnel:SEND abc\n"[..],
            b"@@sshunnel:SEND abc lots\n",
            b"@@sshunnel:READY abc\n",
            b"@@sshunnel:HELLO\n",
            b"@@sshunnel:\xff\n",
        ] {
            assert!(parse_line(raw).unwrap().is_err(), "{}", String::from_utf8_lossy(raw));
        }
    }
}
