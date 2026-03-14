use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use anyhow::anyhow;

pub fn init(store_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    let store_dir = store_dir.as_ref();
    eprintln!("Initializing Git repository in {}", store_dir.display());
    let mut command = Command::new("git");
    command.stdin(Stdio::null());
    command.arg("-C");
    command.arg(store_dir);
    command.arg("init");
    let status = command.status()?;
    if !status.success() {
        return Err(anyhow!("Git repository initialization failed"));
    }
    Ok(())
}

pub fn add_and_commit(
    store_dir: impl AsRef<Path>,
    files: impl IntoIterator<Item = impl AsRef<Path>>,
    message: &str,
) -> anyhow::Result<()> {
    let store_dir = store_dir.as_ref();
    eprintln!("Adding files to git repository");
    {
        let mut command = Command::new("git");
        command.stdin(Stdio::null());
        command.arg("-C");
        command.arg(store_dir);
        command.arg("add");
        for file in files.into_iter() {
            command.arg(file.as_ref());
        }
        let status = command.status()?;
        if !status.success() {
            return Err(anyhow!("Failed to add files to Git repository"));
        }
    }
    {
        let mut command = Command::new("git");
        command.stdin(Stdio::null());
        command.arg("-C");
        command.arg(store_dir);
        command.arg("commit");
        command.arg("-m");
        command.arg(message);
        let status = command.status()?;
        if !status.success() {
            return Err(anyhow!("Failed to commit changes to Git"));
        }
    }
    Ok(())
}

pub fn remove_and_commit(
    store_dir: impl AsRef<Path>,
    files: impl IntoIterator<Item = impl AsRef<Path>>,
    message: &str,
) -> anyhow::Result<()> {
    let store_dir = store_dir.as_ref();
    eprintln!("Removing files from git repository");
    {
        let mut command = Command::new("git");
        command.stdin(Stdio::null());
        command.arg("-C");
        command.arg(store_dir);
        command.arg("rm");
        for file in files.into_iter() {
            command.arg(file.as_ref());
        }
        let status = command.status()?;
        if !status.success() {
            return Err(anyhow!("Failed to remove files from Git repository"));
        }
    }
    {
        let mut command = Command::new("git");
        command.stdin(Stdio::null());
        command.arg("-C");
        command.arg(store_dir);
        command.arg("commit");
        command.arg("-m");
        command.arg(message);
        let status = command.status()?;
        if !status.success() {
            return Err(anyhow!("Failed to commit changes to Git"));
        }
    }
    Ok(())
}
