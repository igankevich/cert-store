#![doc = include_str!("../README.md")]
#![doc(hidden)]

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use anyhow::anyhow;
use clap::Parser;
use clap::Subcommand;
use zeroizing_alloc::ZeroAlloc;

mod cert;
mod git;
mod gpg;

use self::cert::CERT_PEM;
use self::cert::CertificateConfig;
use self::cert::KEY_PEM_GPG;

const ONE_DAY_IN_SECONDS: u64 = 24 * 60 * 60;
const ONE_YEAR_IN_SECONDS: u64 = 365 * ONE_DAY_IN_SECONDS;
const TEN_YEARS: Duration = Duration::from_secs(10 * ONE_YEAR_IN_SECONDS);
const ONE_YEAR: Duration = Duration::from_secs(ONE_YEAR_IN_SECONDS);

#[derive(clap::Parser)]
struct Args {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum ExportFormat {
    /// PKCS12 (NAME.pfx).
    #[value(alias("pfx"))]
    Pkcs12,
    /// PEM (NAME.crt and NAME.key).
    Pem,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum CertificateKind {
    /// Root (self-signed) certificate.
    #[value(alias("ca"))]
    Root,
    /// Client certificate.
    Client,
    /// Server certificate.
    Server,
}

#[derive(Subcommand)]
enum CliCommand {
    /// Initialize certificate store.
    ///
    /// You can override store directory with `CERT_STORE_DIR` environment variable.
    Init {
        /// Expiration period of the root certificate in days.
        ///
        /// Default period is 10 years.
        #[clap(short = 'd', long = "expires-in", value_parser = parse_days)]
        expires_in: Option<Duration>,
    },

    /// Generate key pair and leaf/root certificate.
    Insert {
        /// Certificate type.
        #[clap(action, short = 't', long = "type")]
        kind: CertificateKind,

        /// Expiration period in days.
        ///
        /// Default period is 10 years for root and client certificates
        /// and 1 year for server certificates.
        #[clap(short = 'd', long = "expires-in", value_parser = parse_days)]
        expires_in: Option<Duration>,

        /// Common name of the parent (root) certificate.
        ///
        /// If not specified, the default one is used.
        #[clap(short = 'p', long = "parent")]
        parent_common_name: Option<String>,

        /// Common name.
        #[clap(num_args = 1..)]
        names: Vec<String>,
    },

    /// Remove key pair and certificate from the store.
    Remove {
        /// Certificate names to delete.
        #[clap(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
        names: Vec<String>,
    },

    /// List all certificates in the store.
    List,

    /// Decrypt and print key from the store.
    ShowKey {
        /// Copy to clipboard instead of printing to stdout.
        #[clap(short = 'c', long = "clip")]
        clip: bool,

        /// Common name.
        name: String,
    },

    /// Print certificate from the store.
    ShowCert {
        /// Copy to clipboard instead of printing to stdout.
        #[clap(short = 'c', long = "clip")]
        clip: bool,

        /// Common name.
        name: String,
    },

    /// Export key and certificate.
    Export {
        /// Output format.
        #[clap(short = 'f', long = "format", default_value = "pem")]
        format: ExportFormat,

        /// Common name.
        name: String,

        /// Output directory.
        output_dir: PathBuf,
    },

    /// Run `git` command inside store directory.
    Git {
        /// Arguments to pass to `git` command.
        #[clap(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        CliCommand::Init { expires_in } => {
            let store_dir = cert_store_dir();
            eprintln!("Creating store directory {}", store_dir.display());
            fs::create_dir_all(&store_dir)?;
            git::init(&store_dir)?;
            gpg::init_recipients(&store_dir)?;
            let cn = root_common_name();
            let config = CertificateConfig::Root { cn };
            cert::generate(&store_dir, config, expires_in.unwrap_or(TEN_YEARS))?;
        }
        CliCommand::Insert {
            kind,
            expires_in,
            mut names,
            parent_common_name,
        } => {
            assert!(!names.is_empty());
            let store_dir = cert_store_dir();
            let config = match kind {
                CertificateKind::Root => {
                    if names.len() != 1 {
                        return Err(anyhow!(
                            "You should supply exactly one name for root certificate"
                        ));
                    }
                    if parent_common_name.is_some() {
                        return Err(anyhow!("Root certificate can't have a parent"));
                    }
                    let cn = std::mem::take(&mut names[0]);
                    CertificateConfig::Root { cn }
                }
                CertificateKind::Client => {
                    if names.len() != 1 {
                        return Err(anyhow!(
                            "You should supply exactly one name for client certificate"
                        ));
                    }
                    let cn = std::mem::take(&mut names[0]);
                    let parent_cn = parent_common_name.unwrap_or_else(root_common_name);
                    CertificateConfig::Client { cn, parent_cn }
                }
                CertificateKind::Server => {
                    let parent_cn = parent_common_name.unwrap_or_else(root_common_name);
                    CertificateConfig::Server { names, parent_cn }
                }
            };
            let expires_in = match expires_in {
                Some(expires_in) => expires_in,
                None => match kind {
                    CertificateKind::Root | CertificateKind::Client => TEN_YEARS,
                    CertificateKind::Server => ONE_YEAR,
                },
            };
            cert::generate(&store_dir, config, expires_in)?;
        }
        CliCommand::Remove { names } => {
            let store_dir = cert_store_dir();
            for name in names.into_iter() {
                if let Err(e) = cert::remove(&store_dir, &name) {
                    eprintln!("Failed to remove {name:?}: {e}");
                }
            }
        }
        CliCommand::List => {
            cert::list(cert_store_dir())?;
        }
        CliCommand::ShowKey { clip, name } => {
            let store_dir = cert_store_dir();
            let cn_dir = store_dir.join(&name);
            let key_pem = gpg::decrypt(cn_dir.join(KEY_PEM_GPG))?;
            if clip {
                copy_to_clipboard(key_pem.as_bytes())?;
            } else {
                print!("{key_pem}");
            }
        }
        CliCommand::ShowCert { clip, name } => {
            let store_dir = cert_store_dir();
            let cn_dir = store_dir.join(&name);
            let cert_pem = fs::read_to_string(cn_dir.join(CERT_PEM))?;
            if clip {
                copy_to_clipboard(cert_pem.as_bytes())?;
            } else {
                print!("{cert_pem}");
            }
        }
        CliCommand::Export {
            format,
            name,
            output_dir,
        } => {
            let store_dir = cert_store_dir();
            let cn_dir = store_dir.join(&name);
            let key_pem = gpg::decrypt(cn_dir.join(KEY_PEM_GPG))?;
            fs::create_dir_all(&output_dir)?;
            let output_cert_file = output_dir.join(format!("{name}.crt"));
            let output_key_file = output_dir.join(format!("{name}.key"));
            let output_pfx_file = output_dir.join(format!("{name}.pfx"));
            let root_cert_file = store_dir.join(&name).join(CERT_PEM);
            fs::copy(cn_dir.join(CERT_PEM), &output_cert_file)?;
            unsafe { libc::umask(0o077) };
            fs::write(&output_key_file, &key_pem)?;
            match format {
                ExportFormat::Pem => {}
                ExportFormat::Pkcs12 => {
                    return Err(Command::new("openssl")
                        .arg("pkcs12")
                        .arg("-export")
                        .arg("-out")
                        .arg(&output_pfx_file)
                        .arg("-inkey")
                        .arg(&output_key_file)
                        .arg("-in")
                        .arg(&output_cert_file)
                        .arg("-certfile")
                        .arg(&root_cert_file)
                        .exec()
                        .into());
                }
            }
        }
        CliCommand::Git { args } => {
            return Err(Command::new("git")
                .current_dir(cert_store_dir())
                .args(args)
                .exec()
                .into());
        }
    }
    Ok(())
}

fn root_common_name() -> String {
    std::env::var("USER")
        .ok()
        .unwrap_or_else(|| "root".to_string())
}

fn cert_store_dir() -> PathBuf {
    match std::env::var_os("CERT_STORE_DIR") {
        Some(cert_store_dir) => cert_store_dir.into(),
        None => std::env::home_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join(".cert-store"),
    }
}

fn copy_to_clipboard(data: &[u8]) -> anyhow::Result<()> {
    let mut command = Command::new("xclip");
    command.stdin(Stdio::piped());
    command.arg("-selection");
    command.arg("clipboard");
    let mut child = command.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data)?;
        drop(stdin);
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("Copying to clipboard failed"));
    }
    Ok(())
}

fn parse_days(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    let s = match s.strip_suffix("d") {
        Some(s) => s.trim(),
        None => s,
    };
    let days: u64 = s.parse()?;
    let secs = days
        .checked_mul(ONE_DAY_IN_SECONDS)
        .ok_or_else(|| anyhow!("Value is too large"))?;
    Ok(Duration::from_secs(secs))
}

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);
