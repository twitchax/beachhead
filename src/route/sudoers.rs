//! `sshunnel sudoers`: the one-time setup that lets `route` start its root helper without a sudo
//! password, printed as a script for a person to read and run. sshunnel changes nothing itself.
//!
//! sudo runs whatever is at the path a `NOPASSWD` line names, so whoever can write that file, or
//! any directory above it, is root. The script therefore names only a binary root alone can write
//! ([`root_only`]), installing this one in [`INSTALL_DIR`] first when it isn't, and refuses a name
//! or path sudoers or the shell could read as more than itself.

use std::{fmt::Write as _, os::unix::fs::MetadataExt as _, path::Path, process::Stdio};

use anyhow::{Context as _, bail, ensure};

use crate::{
    base::Res,
    route::helper::{self, Sudo},
};

/// Where the script installs a binary that users other than root can write.
pub const INSTALL_DIR: &str = "/usr/local/bin";

/// What `sudoers` says as root: the sudoers line names the user who runs `route`.
const AS_ROOT: &str = "run `sshunnel sudoers` as the user who will run route, not as root";

/// The script's opening, before its steps.
const HEADER: &str = "# route starts a root helper through sudo. Run this once, as yourself, to let it start without a
# password. Read it first: sudo runs whatever is at the path the sudoers line names.
";

/// The setup for the user running this, and for this binary: [`script`] with what it finds, sudo's
/// answer from [`helper::probe_sudo`].
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
    ensure!(
        exe_root_only || root_only(Path::new(INSTALL_DIR))?,
        "{INSTALL_DIR} can be written by users other than root, so a sudoers line can't safely name a binary in it; \
         install sshunnel in a directory only root can write, and run `sshunnel sudoers` from that copy"
    );
    script(&user_name()?, &exe, exe_root_only, helper::probe_sudo().await?)
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

/// The setup script for `user` and the binary at `exe`: install it in [`INSTALL_DIR`] unless
/// `exe_root_only`, allow its helper in a sudoers file, and say what `sudo` does right now.
///
/// # Errors
///
/// Fails for [`Sudo::AlreadyRoot`] (the line names the user who runs `route`, never root), for a
/// relative `exe`, and for a `user` or `exe` with anything but `[A-Za-z0-9._/+-]`, all of which
/// mean only themselves to sudoers and to the shell.
pub fn script(user: &str, exe: &Path, exe_root_only: bool, sudo: Sudo) -> Res<String> {
    let now = match sudo {
        Sudo::AlreadyRoot => bail!(AS_ROOT),
        Sudo::NoPrompt => "sudo starts the helper without a password: this is already set up",
        Sudo::Prompts => "sudo asks for a password to start the helper",
    };
    let user = plain("the user name", user)?;
    ensure!(exe.is_absolute(), "sudoers needs a full path, and {} is relative", exe.display());
    let exe = plain("the path", exe.to_str().with_context(|| format!("{} isn't UTF-8", exe.display()))?)?;
    let installed = format!("{INSTALL_DIR}/sshunnel");
    let named = if exe_root_only { exe } else { &installed };

    let mut steps = Vec::with_capacity(3);
    if !exe_root_only {
        steps.push(format!("Install sshunnel where only root can write.\nsudo install -o root -g root -m 0755 {exe} {installed}"));
    }
    steps.push(format!(
        "Allow the helper, and nothing else, without a password. visudo checks the line first.\n\
         f=$(mktemp) &&\n  \
         printf '%s\\n' '{user} ALL=(root) NOPASSWD: {named} helper --socket *' > \"$f\" &&\n  \
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

    use std::{fs::Permissions, os::unix::fs::PermissionsExt as _};

    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;
    use crate::tests::netns;

    #[test]
    fn sudoers_script_installs_a_binary_others_can_write() {
        let script = script("me", Path::new("/home/me/.cargo/bin/sshunnel"), false, Sudo::Prompts).unwrap();

        assert_eq!(
            script,
            r#"# route starts a root helper through sudo. Run this once, as yourself, to let it start without a
# password. Read it first: sudo runs whatever is at the path the sudoers line names.

# 1. Install sshunnel where only root can write.
sudo install -o root -g root -m 0755 /home/me/.cargo/bin/sshunnel /usr/local/bin/sshunnel

# 2. Allow the helper, and nothing else, without a password. visudo checks the line first.
f=$(mktemp) &&
  printf '%s\n' 'me ALL=(root) NOPASSWD: /usr/local/bin/sshunnel helper --socket *' > "$f" &&
  sudo visudo -cf "$f" && sudo install -o root -g root -m 0440 "$f" /etc/sudoers.d/sshunnel
rm -f "$f"

# 3. Run route as /usr/local/bin/sshunnel: a copy earlier on PATH (~/.cargo/bin, say) still prompts.

# Right now, sudo asks for a password to start the helper.
"#
        );
    }

    #[test]
    fn sudoers_script_names_a_root_only_binary_as_is() {
        let script = script("me", Path::new("/usr/bin/sshunnel"), true, Sudo::NoPrompt).unwrap();

        assert!(!script.contains("install -o root -g root -m 0755"), "{script}");
        assert!(script.contains("\n# 1. Allow the helper"), "the steps renumber: {script}");
        assert!(script.contains("'me ALL=(root) NOPASSWD: /usr/bin/sshunnel helper --socket *'"), "{script}");
        assert!(!script.contains("Run route as"), "{script}");
        assert_eq!(script.lines().last(), Some("# Right now, sudo starts the helper without a password: this is already set up."));
    }

    #[test]
    fn sudoers_script_refuses_characters_sudoers_would_misread() {
        let exe = Path::new("/home/me/.cargo/bin/sshunnel");
        for user in ["a b", "", "me,root", "%sudo", "me\nroot", "me'", "me#"] {
            let error = script(user, exe, false, Sudo::Prompts).unwrap_err().to_string();
            assert!(error.contains("user name"), "{user:?}: {error}");
        }
        for path in ["/opt/my tools/sshunnel", "/opt/*/sshunnel", "/opt/it's/sshunnel", "/opt/a,b/sshunnel", "/opt/a\\b/sshunnel"] {
            for root_only in [false, true] {
                let error = script("me", Path::new(path), root_only, Sudo::Prompts).unwrap_err().to_string();
                assert!(error.contains("path"), "{path:?}: {error}");
            }
        }
        // sudoers takes a command by its full path only.
        assert!(script("me", Path::new("sshunnel"), true, Sudo::Prompts).is_err());
    }

    #[test]
    fn sudoers_script_is_not_for_root() {
        let error = script("root", Path::new("/usr/bin/sshunnel"), true, Sudo::AlreadyRoot).unwrap_err();

        assert_eq!(error.to_string(), "run `sshunnel sudoers` as the user who will run route, not as root");
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
