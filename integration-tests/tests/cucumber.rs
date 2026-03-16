use cucumber::World;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

mod steps;

/// Return the most recent modification time found under `dir` (recursively).
/// Returns `None` when the directory does not exist or is empty.
fn newest_mtime_in_dir(dir: &Path) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return None,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let candidate = if path.is_dir() {
            newest_mtime_in_dir(&path)
        } else {
            path.metadata().ok().and_then(|m| m.modified().ok())
        };
        if let Some(t) = candidate {
            newest = Some(match newest {
                Some(cur) if cur >= t => cur,
                _ => t,
            });
        }
    }
    newest
}

/// Check whether any source file is newer than the compiled binary.
///
/// Compares the modification time of `binary` against every file under the
/// directories / files listed in `watched`.  Returns `true` when a rebuild is
/// required (binary missing **or** a source file is newer).
fn needs_rebuild(binary: &Path, watched: &[PathBuf]) -> bool {
    let bin_mtime = match binary.metadata().and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return true, // binary does not exist yet
    };

    for path in watched {
        let newest = if path.is_dir() {
            newest_mtime_in_dir(path)
        } else {
            path.metadata().ok().and_then(|m| m.modified().ok())
        };
        if let Some(t) = newest
            && t > bin_mtime
        {
            return true;
        }
    }
    false
}

/// Ensure the minotari binary is built and up-to-date before running tests.
///
/// Compares source-file timestamps against the compiled binary.  If nothing
/// has changed the existing binary is reused as-is — no cargo invocation at all.
/// When a source file *is* newer, `cargo build` is invoked so the tests always
/// exercise the latest code.
fn ensure_minotari_binary_built() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().expect("Failed to find workspace root");

    let profile = if cfg!(debug_assertions) { "dev" } else { "release" };

    let target_dir = if profile == "release" { "release" } else { "debug" };

    let binary = workspace_root.join(format!("target/{target_dir}/minotari"));

    // Paths whose changes should trigger a rebuild.
    let watched: Vec<PathBuf> = vec![
        workspace_root.join("minotari/src"),
        workspace_root.join("minotari/migrations"),
        workspace_root.join("minotari/Cargo.toml"),
        workspace_root.join("Cargo.lock"),
    ];

    if !needs_rebuild(&binary, &watched) {
        eprintln!("minotari binary is up-to-date, skipping rebuild.");
        return;
    }

    eprintln!("Source changes detected — rebuilding minotari (profile={profile})…");
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--package", "minotari", "--bin", "minotari"]);
    if profile == "release" {
        cmd.arg("--release");
    }
    cmd.current_dir(workspace_root);

    let status = cmd.status().expect("Failed to execute cargo build");
    assert!(
        status.success(),
        "cargo build for minotari failed with status: {status}"
    );
    eprintln!("minotari binary rebuilt successfully.");
}

#[tokio::main]
async fn main() {
    ensure_minotari_binary_built();

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let features_path = manifest_dir.join("features");

    steps::MinotariWorld::cucumber()
        .max_concurrent_scenarios(1)
        .run(features_path)
        .await;
}
