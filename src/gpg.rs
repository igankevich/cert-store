use std::fmt::Write as _;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read as _;
use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use anyhow::anyhow;

use crate::git;
use crate::gpg;

const RECIPIENTS: &str = ".recipients";

pub fn init_recipients(store_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    println!("Choose GPG public keys that will be able to decrypt the data:");
    let public_keys = gpg::list_keys()?;
    if public_keys.is_empty() {
        return Err(anyhow!("There no keys in GPG store"));
    }
    for (i, (id, user)) in public_keys.iter().enumerate() {
        let n = i + 1;
        println!("{n:>3}    {id}    {user}");
    }
    let mut indices = Vec::new();
    'outer: loop {
        indices.clear();
        print!("Type space-separated row numbers: ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        for s in answer.trim().split_whitespace() {
            let number: usize = match s.parse() {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("{s:?}: {e}");
                    continue 'outer;
                }
            };
            if number == 0 || number >= public_keys.len() {
                eprintln!("Out-of-range number: {s:?}");
                continue 'outer;
            }
            indices.push(number - 1);
        }
        break;
    }
    let gpg_id_file = store_dir.as_ref().join(RECIPIENTS);
    eprintln!("Generating recipients file {}", gpg_id_file.display());
    let mut file = BufWriter::new(fs::File::create(&gpg_id_file)?);
    let mut commit_message = "Added recipients: ".to_string();
    for (iteration, i) in indices.iter().copied().enumerate() {
        let (public_key, user) = &public_keys[i];
        writeln!(&mut file, "{}", public_key)?;
        if iteration == 0 {
            write!(&mut commit_message, "{public_key} ({user})")?;
        } else {
            write!(&mut commit_message, ", {public_key} ({user})")?;
        }
    }
    drop(file);
    git::add_and_commit(store_dir, [&gpg_id_file], &commit_message)?;
    Ok(())
}

pub fn recipients(store_dir: impl AsRef<Path>) -> anyhow::Result<Vec<String>> {
    let file = fs::File::open(store_dir.as_ref().join(RECIPIENTS))?;
    let reader = BufReader::new(file);
    let mut recipients = Vec::new();
    for line in reader.lines() {
        let line = line?;
        recipients.push(line.trim().to_string());
    }
    Ok(recipients)
}

pub fn encrypt(
    data: &[u8],
    output_file: impl AsRef<Path>,
    recipients: impl IntoIterator<Item = impl AsRef<str>>,
) -> anyhow::Result<()> {
    let mut command = Command::new("gpg");
    command.stdin(Stdio::piped());
    command.arg("--quiet");
    command.arg("--encrypt");
    command.arg("--output");
    command.arg(output_file.as_ref());
    for recipient in recipients.into_iter() {
        command.arg("--recipient");
        command.arg(recipient.as_ref());
    }
    let mut child = command.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data)?;
        drop(stdin);
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("Encryption failed"));
    }
    Ok(())
}

pub fn decrypt(input_file: impl AsRef<Path>) -> anyhow::Result<String> {
    let mut command = Command::new("gpg");
    command.stdout(Stdio::piped());
    command.arg("--quiet");
    command.arg("--decrypt");
    command.arg(input_file.as_ref());
    let mut child = command.spawn()?;
    let mut buf = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut buf)?;
        drop(stdout);
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("Decryption failed"));
    }
    Ok(String::from_utf8(buf)?)
}

pub fn list_keys() -> anyhow::Result<Vec<(String, String)>> {
    let invalid = || anyhow!("Invalid `gpg --list-keys --with-colons` output");
    let mut command = Command::new("gpg");
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.args(["--list-keys", "--with-colons"]);
    let mut child = command.spawn()?;
    let mut public_keys = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        let mut public_key = None;
        for line in reader.lines() {
            let line = line?;
            let mut columns = line.split(':');
            let kind = columns.next().ok_or_else(invalid)?;
            match kind {
                "tru" | "fpr" | "sub" => continue,
                "pub" => public_key = Some(columns.nth(3).ok_or_else(invalid)?.to_owned()),
                "uid" => {
                    let Some(public_key) = public_key.take() else {
                        continue;
                    };
                    let user = columns.nth(8).ok_or_else(invalid)?;
                    public_keys.push((public_key, user.to_owned()));
                }
                _ => {}
            }
        }
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("Decryption failed"));
    }
    Ok(public_keys)
}
