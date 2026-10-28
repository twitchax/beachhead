//! `sshunnel sudoers`: the one-time setup that lets `route` start its root helper without a sudo
//! password, printed as a script for a person to read and run. sshunnel changes nothing itself.
//!
//! sudo runs whatever is at the path a `NOPASSWD` line names, so whoever can write that file, or
//! any directory above it, is root. The script therefore names only a binary root alone can write
//! ([`root_only`]), installing this one in [`INSTALL_DIR`] first when it isn't. It refuses a path
//! with a character sudoers or the shell could misread. The line names the user's uid (`#1000`), which
//! sudoers can't read as `ALL`, a `+netgroup` or a `User_Alias`, with the login name only as a comment.

use std::{
    borrow::Cow,
    fmt::Write as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context as _, bail, ensure};

use crate::{
    base::Res,
    route::helper::{self, Sudo},
};

/// Where the script installs a binary that users other than root can write.
pub const INSTALL_DIR: &str = "/usr/local/bin";

/// Where `sudoers` suggests a root-owned copy when [`INSTALL_DIR`] isn't root's alone. `install -D`
/// makes the directories it lacks, as root.
const ELSEWHERE: &str = "/opt/sshunnel/bin/sshunnel";

/// What `sudoers` says as root: the sudoers line names the user who runs `route`.
const AS_ROOT: &str = "run `sshunnel sudoers` as the user who will run route, not as root";

/// The script's opening, before its steps.
const HEADER: &str = "# route starts a root helper through sudo. Run this once, as yourself, to let it start without a
# password. Read it first: sudo runs whatever is at the path the sudoers line names.
";

/// What sudo does with the helper, as `ask` found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answers {
    /// For the helper as this binary starts it.
    pub this: Sudo,
    /// For the helper as the copy in [`INSTALL_DIR`] starts it, when `ask` asked about that one too.
    pub installed: Option<Sudo>,
}

/// The setup for the user running this, and for this binary: [`script`] with what it finds, and
/// sudo's answers from `ask`.
///
/// # Errors
///
/// Fails as root, when neither this binary nor [`INSTALL_DIR`] is [`root_only`] (no line could
/// safely name either), and when the user's name, this binary's path or sudo's answer can't be had,
/// or [`script`] refuses them.
pub async fn run() -> Res<String> {
    ensure!(!rustix::process::geteuid().is_root(), AS_ROOT);
    let exe = std::env::current_exe().context("locating sshunnel's own executable")?;
    let exe_root_only = root_only(&exe)?;
    if !exe_root_only && !root_only(Path::new(INSTALL_DIR))? {
        bail!(unsafe_install_dir(&exe, elsewhere_writable()?.as_deref()));
    }
    let answers = ask(&exe, exe_root_only, installed_root_only()?.as_deref(), helper::probe_sudo_for).await?;
    script(&label_name(), &exe, exe_root_only, answers)
}

/// [`ask`] about this binary, with the copy in [`INSTALL_DIR`] as this machine has it.
///
/// # Errors
///
/// Fails as [`ask`] does, and when this binary or that copy can't be located or read.
pub(crate) async fn ask_sudo() -> Res<Answers> {
    let exe = std::env::current_exe().context("locating sshunnel's own executable")?;
    ask(&exe, root_only(&exe)?, installed_root_only()?.as_deref(), helper::probe_sudo_for).await
}

/// Asks sudo, through `probe`, about the helper as the binary at `exe` starts it. When sudo asks
/// for a password, no sudoers line can name `exe` (it isn't [`root_only`]), and `installed` is a
/// root-only copy in [`INSTALL_DIR`] other than `exe`, it asks about that copy too: an earlier
/// setup may have allowed it, and then `route` started from it needs no password. A failure there
/// only leaves that answer out, since this binary's answer stands either way.
///
/// # Errors
///
/// Fails when `probe` does for `exe`.
pub(crate) async fn ask(exe: &Path, exe_root_only: bool, installed: Option<&Path>, probe: impl AsyncFn(&Path) -> Res<Sudo>) -> Res<Answers> {
    let this = probe(exe).await?;
    let installed = match installed {
        Some(installed) if this == Sudo::Prompts && !exe_root_only && installed != exe => {
            probe(installed).await.inspect_err(|e| tracing::warn!("asking sudo about {}'s helper: {e:#}", installed.display())).ok()
        }
        _ => None,
    };
    Ok(Answers { this, installed })
}

/// Where the script installs a binary others can write: `sshunnel` in [`INSTALL_DIR`].
pub(crate) fn installed_path() -> String {
    format!("{INSTALL_DIR}/sshunnel")
}

/// The copy in [`INSTALL_DIR`], when there is one and it is [`root_only`].
fn installed_root_only() -> Res<Option<PathBuf>> {
    let installed = PathBuf::from(installed_path());
    Ok((installed.exists() && root_only(&installed)?).then_some(installed))
}

/// Why `sudoers` refuses when neither this binary nor [`INSTALL_DIR`] is [`root_only`], and the way
/// forward: a root-owned copy at [`ELSEWHERE`], run as both `sudoers` and `route`, since its line
/// names that copy and only a copy in [`INSTALL_DIR`] gets pointed back at. When `writable`, a
/// directory on the way there that others can write, rules that out, it says so instead; and it
/// prints the command only for an `exe` the shell reads as written ([`plain`]).
fn unsafe_install_dir(exe: &Path, writable: Option<&Path>) -> String {
    let refused = format!("{INSTALL_DIR} can be written by users other than root, so a sudoers line can't safely name a binary in it");
    match (writable, exe.to_str().and_then(|exe| plain("the path", exe).ok())) {
        (Some(dir), _) => format!(
            "{refused}; {} can be too, so install sshunnel in another directory only root can write, and run both sudoers and route as that copy",
            dir.display()
        ),
        (None, Some(exe)) => format!(
            "{refused}; install a root-owned copy where only root can write, as `sudo install -D -o root -g root -m 0755 {exe} {ELSEWHERE}` does, \
             then run both sudoers and route as that copy: `{ELSEWHERE} sudoers`"
        ),
        (None, None) => format!("{refused}; install sshunnel in a directory only root can write, and run both sudoers and route as that copy"),
    }
}

/// The first directory over [`ELSEWHERE`] that others can write, of those there already: the
/// nearest one, resolved, and those above it.
fn elsewhere_writable() -> Res<Option<PathBuf>> {
    let nearest = Path::new(ELSEWHERE).ancestors().skip(1).find(|dir| dir.exists()).unwrap_or(Path::new("/"));
    let nearest = nearest.canonicalize().with_context(|| format!("resolving {}", nearest.display()))?;
    Ok(first_writable(&nearest)?.map(Path::to_path_buf))
}

/// Whether root alone can write `path`: it and every directory above it are owned by root and have
/// neither the group-write nor the other-write bit. Each is taken as it is (`symlink_metadata`),
/// and a symlink's mode lets anyone write, so pass a path whose components are already resolved.
///
/// # Errors
///
/// Fails when `path` is relative or one of them can't be read.
pub fn root_only(path: &Path) -> Res<bool> {
    Ok(first_writable(path)?.is_none())
}

/// The first of `path` and the directories above it, from `path` up, that root doesn't own or
/// someone else can write.
fn first_writable(path: &Path) -> Res<Option<&Path>> {
    ensure!(path.is_absolute(), "{} is not an absolute path", path.display());
    for entry in path.ancestors() {
        let meta = std::fs::symlink_metadata(entry).with_context(|| format!("reading {}", entry.display()))?;
        if !root_writes_alone(meta.uid(), meta.mode()) {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

/// Whether a file with this owner and mode can be written by root alone.
fn root_writes_alone(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

/// This user's name, as `id -un` prints it.
///
/// # Errors
///
/// Fails when `id` can't be run or fails.
pub fn user_name() -> Res<String> {
    let id = std::process::Command::new("id").arg("-un").stdin(Stdio::null()).output().context("running id -un")?;
    ensure!(id.status.success(), "id -un failed ({}): {}", id.status, String::from_utf8_lossy(&id.stderr).trim());
    Ok(String::from_utf8(id.stdout).context("reading id -un's output")?.trim().to_owned())
}

/// The name that labels the sudoers line, or none when `id -un` fails: the line stands without it.
fn label_name() -> String {
    user_name()
        .inspect_err(|e| tracing::warn!("labeling the sudoers line without the user name: {e:#}"))
        .unwrap_or_default()
}

/// The setup script for the user running this (labeled `user`) and the binary at `exe`: install it
/// in [`INSTALL_DIR`] unless `exe_root_only`, allow its helper in a sudoers file, and say what `sudo`
/// does right now.
///
/// # Errors
///
/// Fails for [`Sudo::AlreadyRoot`] (the line names the user who runs `route`, never root), for a
/// relative `exe`, and for an `exe` with anything but `[A-Za-z0-9._/+-]`, which means only itself to
/// sudoers and to the shell. The line names the user's uid (`#1000`), so no `user` is refused: one
/// that is empty or has other characters just goes unlabeled.
pub fn script(user: &str, exe: &Path, exe_root_only: bool, sudo: Answers) -> Res<String> {
    let installed = installed_path();
    let now: Cow<str> = match sudo {
        Answers { this: Sudo::AlreadyRoot, .. } => bail!(AS_ROOT),
        Answers { this: Sudo::NoPrompt, .. } => "sudo starts the helper without a password: this is already set up".into(),
        Answers {
            this: Sudo::Prompts,
            installed: Some(Sudo::NoPrompt),
        } => format!("sudo starts {installed}'s helper without a password: run route as it").into(),
        Answers { this: Sudo::Prompts, .. } => "sudo asks for a password to start the helper".into(),
    };
    // The rule names the uid, which sudoers can't read as anything else, so no login name is refused;
    // the name is only a comment above it, and only when it can't end that comment's line early.
    let uid = rustix::process::getuid().as_raw();
    let label = plain("the user name", user).ok().map(|user| format!("'# {user}' ")).unwrap_or_default();
    ensure!(exe.is_absolute(), "sudoers needs a full path, and {} is relative", exe.display());
    let exe = plain("the path", exe.to_str().with_context(|| format!("{} isn't UTF-8", exe.display()))?)?;
    let named = if exe_root_only { exe } else { &installed };

    let mut steps = Vec::with_capacity(3);
    if !exe_root_only {
        steps.push(format!("Install sshunnel where only root can write.\nsudo install -o root -g root -m 0755 {exe} {installed}"));
    }
    steps.push(format!(
        "Allow the helper, and nothing else, without a password. visudo checks the line first.\n\
         f=$(mktemp) &&\n  \
         printf '%s\\n' {label}'#{uid} ALL=(root) NOPASSWD: {named} helper --socket *' > \"$f\" &&\n  \
         sudo visudo -cf \"$f\" && sudo install -o root -g root -m 0440 \"$f\" /etc/sudoers.d/sshunnel\n\
         rm -f \"$f\""
    ));
    if !exe_root_only {
        steps.push(format!("Run route as {installed}: a copy earlier on PATH (~/.cargo/bin, say) still prompts."));
    }

    let mut out = String::from(HEADER);
    for (n, step) in (1..).zip(&steps) {
        let _ = write!(out, "\n# {n}. {step}\n");
    }
    let _ = write!(out, "\n# Right now, {now}.\n");
    Ok(out)
}

/// `text`, refused when empty or holding anything but `[A-Za-z0-9._/+-]`.
fn plain<'a>(what: &str, text: &'a str) -> Res<&'a str> {
    let safe = |c: char| c.is_ascii_alphanumeric() || "._/+-".contains(c);
    ensure!(
        !text.is_empty() && text.chars().all(safe),
        "{what} {text:?} isn't safe in a sudoers line: only A-Z, a-z, 0-9 and ._/+- are"
    );
    Ok(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{cell::RefCell, fs::Permissions, os::unix::fs::PermissionsExt as _};

    use anyhow::anyhow;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;
    use crate::tests::netns;

    const EXE: &str = "/home/me/.cargo/bin/sshunnel";
    const INSTALLED: &str = "/usr/local/bin/sshunnel";
    const PROMPTS: &str = "# Right now, sudo asks for a password to start the helper.";

    /// sudo's answer for this binary, and none for the installed copy.
    fn only_this(this: Sudo) -> Answers {
        Answers { this, installed: None }
    }

    /// [`ask`] about [`EXE`], with `installed` as the copy in [`INSTALL_DIR`] and sudo answering
    /// each path as `answers` has it (a path it lacks fails); returns what it found and the paths
    /// it asked sudo about.
    async fn asking(exe_root_only: bool, installed: Option<&str>, answers: &[(&str, Sudo)]) -> (Res<Answers>, Vec<PathBuf>) {
        let asked = RefCell::new(Vec::new());
        let probe = async |exe: &Path| {
            asked.borrow_mut().push(exe.to_owned());
            answers.iter().find(|(at, _)| Path::new(at) == exe).map(|(_, sudo)| *sudo).ok_or_else(|| anyhow!("sudo didn't answer"))
        };
        let found = ask(Path::new(EXE), exe_root_only, installed.map(Path::new), probe).await;
        (found, asked.into_inner())
    }

    fn paths(items: &[&str]) -> Vec<PathBuf> {
        items.iter().map(PathBuf::from).collect()
    }

    /// The last line of the script for [`EXE`], which others can write, with these answers.
    fn last_line(answers: Answers) -> String {
        let script = script("me", Path::new(EXE), false, answers).unwrap();
        script.lines().last().unwrap().to_owned()
    }

    fn uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn sudoers_script_names_the_uid_and_labels_it_with_the_name() {
        let script = script("me", Path::new("/usr/bin/sshunnel"), true, only_this(Sudo::Prompts)).unwrap();

        let line = format!("printf '%s\\n' '# me' '#{} ALL=(root) NOPASSWD: /usr/bin/sshunnel helper --socket *' > \"$f\"", uid());
        assert!(script.contains(&line), "{script}");
    }

    #[test]
    fn sudoers_script_takes_any_login_name() {
        let uid = uid();
        for name in ["ALL", "+admins", "ADMIN", "WHEEL_2"] {
            let script = script(name, Path::new("/usr/bin/sshunnel"), true, only_this(Sudo::Prompts)).unwrap();
            assert!(script.contains(&format!("'# {name}' '#{uid} ALL=(root)")), "{script}");
        }
        for name in ["", "o'brien", "a b"] {
            let script = script(name, Path::new("/usr/bin/sshunnel"), true, only_this(Sudo::Prompts)).unwrap();
            assert!(script.contains(&format!("printf '%s\\n' '#{uid} ALL=(root)")), "no label for {name:?}: {script}");
            assert!(!script.contains("'# "), "{script}");
        }
    }

    #[test]
    fn sudoers_visudo_accepts_the_printed_lines() {
        let dir = TempDir::new().unwrap();
        let visudo = |text: &str| {
            let file = dir.path().join("sudoers");
            std::fs::write(&file, text).unwrap();
            std::process::Command::new("visudo").arg("-cf").arg(&file).stdin(Stdio::null()).output()
        };
        let good = visudo(&format!("#{} ALL=(root) NOPASSWD: /usr/bin/true\n", uid()));
        if !good.is_ok_and(|out| out.status.success()) {
            eprintln!("skipped: visudo is missing or rejects a known-good file here");
            return;
        }

        let script = script("me", Path::new("/usr/bin/sshunnel"), true, only_this(Sudo::Prompts)).unwrap();
        let printf = script.lines().find(|line| line.trim_start().starts_with("printf ")).unwrap();
        let args = printf.split_once("' ").map(|(_, args)| args).unwrap().split(" > ").next().unwrap();
        let lines: Vec<&str> = args.split("' '").map(|arg| arg.trim_matches('\'')).collect();
        assert_eq!(lines.len(), 2, "{printf}");

        let out = visudo(&format!("{}\n", lines.join("\n"))).unwrap();
        assert!(out.status.success(), "{lines:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn sudoers_script_installs_a_binary_others_can_write() {
        let script = script("me", Path::new("/home/me/.cargo/bin/sshunnel"), false, only_this(Sudo::Prompts)).unwrap();

        assert_eq!(
            script,
            r#"# route starts a root helper through sudo. Run this once, as yourself, to let it start without a
# password. Read it first: sudo runs whatever is at the path the sudoers line names.

# 1. Install sshunnel where only root can write.
sudo install -o root -g root -m 0755 /home/me/.cargo/bin/sshunnel /usr/local/bin/sshunnel

# 2. Allow the helper, and nothing else, without a password. visudo checks the line first.
f=$(mktemp) &&
  printf '%s\n' '# me' '#{uid} ALL=(root) NOPASSWD: /usr/local/bin/sshunnel helper --socket *' > "$f" &&
  sudo visudo -cf "$f" && sudo install -o root -g root -m 0440 "$f" /etc/sudoers.d/sshunnel
rm -f "$f"

# 3. Run route as /usr/local/bin/sshunnel: a copy earlier on PATH (~/.cargo/bin, say) still prompts.

# Right now, sudo asks for a password to start the helper.
"#
            .replace("{uid}", &uid().to_string())
        );
    }

    #[test]
    fn sudoers_script_names_a_root_only_binary_as_is() {
        let script = script("me", Path::new("/usr/bin/sshunnel"), true, only_this(Sudo::NoPrompt)).unwrap();

        assert!(!script.contains("install -o root -g root -m 0755"), "{script}");
        assert!(script.contains("\n# 1. Allow the helper"), "the steps renumber: {script}");
        assert!(script.contains(&format!("'#{} ALL=(root) NOPASSWD: /usr/bin/sshunnel helper --socket *'", uid())), "{script}");
        assert!(!script.contains("Run route as"), "{script}");
        assert_eq!(script.lines().last(), Some("# Right now, sudo starts the helper without a password: this is already set up."));
    }

    #[test]
    fn sudoers_script_refuses_a_path_the_shell_or_sudoers_would_misread() {
        for path in ["/opt/my tools/sshunnel", "/opt/*/sshunnel", "/opt/it's/sshunnel", "/opt/a,b/sshunnel", "/opt/a\\b/sshunnel"] {
            for root_only in [false, true] {
                let error = script("me", Path::new(path), root_only, only_this(Sudo::Prompts)).unwrap_err().to_string();
                assert!(error.contains("path"), "{path:?}: {error}");
            }
        }
        // sudoers takes a command by its full path only.
        assert!(script("me", Path::new("sshunnel"), true, only_this(Sudo::Prompts)).is_err());
    }

    #[test]
    fn sudoers_script_is_not_for_root() {
        let error = script("root", Path::new("/usr/bin/sshunnel"), true, only_this(Sudo::AlreadyRoot)).unwrap_err();

        assert_eq!(error.to_string(), "run `sshunnel sudoers` as the user who will run route, not as root");
    }

    #[tokio::test]
    async fn sudoers_asks_sudo_about_the_installed_copy_when_this_one_prompts() {
        let (found, asked) = asking(false, Some(INSTALLED), &[(EXE, Sudo::Prompts), (INSTALLED, Sudo::NoPrompt)]).await;

        assert_eq!(
            found.unwrap(),
            Answers {
                this: Sudo::Prompts,
                installed: Some(Sudo::NoPrompt)
            }
        );
        assert_eq!(asked, paths(&[EXE, INSTALLED]));
    }

    #[test]
    fn sudoers_script_says_to_run_route_as_the_installed_copy_sudo_allows() {
        let allowed = Answers {
            this: Sudo::Prompts,
            installed: Some(Sudo::NoPrompt),
        };

        let after = script("me", Path::new(EXE), false, allowed).unwrap();

        // The steps stay; only what sudo does right now changes.
        let before = script("me", Path::new(EXE), false, only_this(Sudo::Prompts)).unwrap();
        let steps = |script: &str| script.lines().count() - 1;
        assert_eq!(after.lines().take(steps(&after)).collect::<Vec<_>>(), before.lines().take(steps(&before)).collect::<Vec<_>>());
        assert_eq!(
            after.lines().last(),
            Some("# Right now, sudo starts /usr/local/bin/sshunnel's helper without a password: run route as it.")
        );
    }

    #[tokio::test]
    async fn sudoers_script_keeps_its_last_line_without_an_installed_copy() {
        let (found, asked) = asking(false, None, &[(EXE, Sudo::Prompts)]).await;

        assert_eq!(asked, paths(&[EXE]));
        assert_eq!(last_line(found.unwrap()), PROMPTS);
    }

    #[tokio::test]
    async fn sudoers_script_keeps_its_last_line_when_the_installed_copy_is_this_binary() {
        let (found, asked) = asking(false, Some(EXE), &[(EXE, Sudo::Prompts)]).await;

        assert_eq!(asked, paths(&[EXE]));
        assert_eq!(last_line(found.unwrap()), PROMPTS);
    }

    #[tokio::test]
    async fn sudoers_script_keeps_its_last_line_when_the_installed_copy_prompts_too() {
        let (found, asked) = asking(false, Some(INSTALLED), &[(EXE, Sudo::Prompts), (INSTALLED, Sudo::Prompts)]).await;

        assert_eq!(asked, paths(&[EXE, INSTALLED]));
        assert_eq!(last_line(found.unwrap()), PROMPTS);
    }

    #[tokio::test]
    async fn sudoers_script_keeps_its_last_line_when_asking_about_the_installed_copy_fails() {
        // This binary's answer stands: the installed copy's is only ever good news.
        let (found, asked) = asking(false, Some(INSTALLED), &[(EXE, Sudo::Prompts)]).await;

        assert_eq!(asked, paths(&[EXE, INSTALLED]));
        assert_eq!(last_line(found.unwrap()), PROMPTS);
    }

    #[tokio::test]
    async fn sudoers_asks_about_the_installed_copy_only_for_a_binary_that_prompts_and_no_line_can_name() {
        let installed_allowed = (INSTALLED, Sudo::NoPrompt);
        for this in [Sudo::AlreadyRoot, Sudo::NoPrompt] {
            let (found, asked) = asking(false, Some(INSTALLED), &[(EXE, this), installed_allowed]).await;
            assert_eq!((found.unwrap(), asked), (only_this(this), paths(&[EXE])), "{this:?}");
        }
        // A root-only binary gets a line of its own.
        let (found, asked) = asking(true, Some(INSTALLED), &[(EXE, Sudo::Prompts), installed_allowed]).await;
        assert_eq!((found.unwrap(), asked), (only_this(Sudo::Prompts), paths(&[EXE])));
        // No answer for this binary is no answer at all.
        let (found, asked) = asking(false, Some(INSTALLED), &[installed_allowed]).await;
        assert_eq!((found.unwrap_err().to_string(), asked), ("sudo didn't answer".to_owned(), paths(&[EXE])));
    }

    const REFUSED: &str = "/usr/local/bin can be written by users other than root, so a sudoers line can't safely name a binary in it";

    #[test]
    fn sudoers_refusal_shows_a_root_only_way_forward() {
        assert_eq!(
            unsafe_install_dir(Path::new(EXE), None),
            format!(
                "{REFUSED}; install a root-owned copy where only root can write, as \
                 `sudo install -D -o root -g root -m 0755 /home/me/.cargo/bin/sshunnel /opt/sshunnel/bin/sshunnel` does, \
                 then run both sudoers and route as that copy: `/opt/sshunnel/bin/sshunnel sudoers`"
            )
        );
    }

    #[test]
    fn sudoers_refusal_prints_no_command_for_a_path_the_shell_could_misread() {
        for exe in ["/home/me/my tools/sshunnel", "/home/me/$(id)/sshunnel", "/home/me/it's/sshunnel"] {
            assert_eq!(
                unsafe_install_dir(Path::new(exe), None),
                format!("{REFUSED}; install sshunnel in a directory only root can write, and run both sudoers and route as that copy"),
                "{exe:?}"
            );
        }
    }

    #[test]
    fn sudoers_refusal_says_when_opt_is_no_better() {
        assert_eq!(
            unsafe_install_dir(Path::new(EXE), Some(Path::new("/opt"))),
            format!("{REFUSED}; /opt can be too, so install sshunnel in another directory only root can write, and run both sudoers and route as that copy")
        );
    }

    #[test]
    fn sudoers_root_only_refuses_a_file_this_user_owns() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("sshunnel");
        std::fs::write(&file, "").unwrap();

        assert!(!root_only(&file).unwrap());
        assert!(root_only(Path::new("sshunnel")).is_err(), "a relative path has no parents to check");
    }

    #[test]
    fn sudoers_root_only_refuses_a_writable_parent() {
        if !netns("route::sudoers::tests::sudoers_root_only_refuses_a_writable_parent").unwrap() {
            return;
        }
        // As root, everything made here is root's: a root-owned binary, 0755, in a 0777 dir.
        let dir = TempDir::new().unwrap();
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, Permissions::from_mode(0o777)).unwrap();
        let file = open.join("sshunnel");
        std::fs::write(&file, "").unwrap();
        std::fs::set_permissions(&file, Permissions::from_mode(0o755)).unwrap();
        assert_eq!(std::fs::symlink_metadata(&file).unwrap().uid(), 0);

        assert!(!root_only(&file).unwrap());
        // The dir is why, not anything above it (the temp dir, say, which anyone can write).
        assert_eq!(first_writable(&file).unwrap(), Some(open.as_path()));
    }

    #[test]
    fn sudoers_root_only_accepts_a_system_binary() {
        let Ok(env) = Path::new("/usr/bin/env").canonicalize() else {
            eprintln!("skipped: no /usr/bin/env");
            return;
        };

        assert!(root_only(&env).unwrap(), "{}", env.display());
    }

    #[test]
    fn sudoers_root_only_wants_root_and_neither_group_nor_other_write() {
        assert!(root_writes_alone(0, 0o100_755));
        assert!(root_writes_alone(0, 0o040_555));
        assert!(!root_writes_alone(1000, 0o100_755), "not root's");
        assert!(!root_writes_alone(0, 0o100_775), "group-writable");
        assert!(!root_writes_alone(0, 0o040_757), "other-writable");
        assert!(!root_writes_alone(0, 0o041_777), "sticky, like /tmp, still other-writable");
        assert!(!root_writes_alone(0, 0o120_777), "a symlink");
    }

    #[test]
    fn sudoers_user_name_is_id_un() {
        let id = std::process::Command::new("id").arg("-un").output().unwrap();

        assert_eq!(user_name().unwrap(), String::from_utf8(id.stdout).unwrap().trim());
    }
}
