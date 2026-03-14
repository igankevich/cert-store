use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::anyhow;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DistinguishedName;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::Issuer;
use rcgen::KeyIdMethod;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use rcgen::PKCS_ECDSA_P256_SHA256;
use rcgen::SanType;

use crate::git;
use crate::gpg;

const CERT_EXPIRES_IN: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);
pub const CERT_PEM: &str = "cert.pem";
pub const KEY_PEM_GPG: &str = "key.pem.gpg";

fn to_distinguished_name(cn: String) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

fn new_certificate_params(
    config: &CertificateConfig,
) -> anyhow::Result<(CertificateParams, String)> {
    let mut params = CertificateParams::default();
    let cn = match config {
        CertificateConfig::Root { cn } | CertificateConfig::Client { cn, .. } => {
            params.distinguished_name = to_distinguished_name(cn.clone());
            cn.to_owned()
        }
        CertificateConfig::Server { names, .. } => {
            let cn = names
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("You should supply at least one name"))?;
            params.distinguished_name = to_distinguished_name(cn.clone());
            for name in names.iter() {
                let san = match name.parse::<IpAddr>() {
                    Ok(ip) => SanType::IpAddress(ip),
                    Err(_) => SanType::DnsName(name.parse()?),
                };
                params.subject_alt_names.push(san);
            }
            cn
        }
    };
    params.not_before = SystemTime::now().into();
    params.not_after = params.not_before + CERT_EXPIRES_IN;
    params.serial_number = None;
    params.name_constraints = None;
    params.crl_distribution_points = Vec::new();
    params.custom_extensions = Vec::new();
    params.use_authority_key_identifier_extension = false;
    params.key_identifier_method = KeyIdMethod::Sha512;
    match config {
        CertificateConfig::Root { .. } => {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            params.extended_key_usages = Vec::new();
        }
        CertificateConfig::Server { .. } | CertificateConfig::Client { .. } => {
            params.is_ca = IsCa::NoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![match config {
                CertificateConfig::Server { .. } => ExtendedKeyUsagePurpose::ServerAuth,
                CertificateConfig::Client { .. } => ExtendedKeyUsagePurpose::ClientAuth,
                _ => unreachable!(),
            }];
        }
    }
    Ok((params, cn))
}

pub enum CertificateConfig {
    Root {
        cn: String,
    },
    Server {
        names: Vec<String>,
        parent_cn: String,
    },
    Client {
        cn: String,
        parent_cn: String,
    },
}

impl CertificateConfig {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Root { .. } => "root",
            Self::Client { .. } => "client",
            Self::Server { .. } => "server",
        }
    }
}

pub fn generate(store_dir: impl AsRef<Path>, config: CertificateConfig) -> anyhow::Result<()> {
    let kind = config.kind();
    let store_dir = store_dir.as_ref();
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let (params, cn) = new_certificate_params(&config)?;
    let certificate = match &config {
        CertificateConfig::Root { .. } => params.self_signed(&key_pair)?,
        CertificateConfig::Server { parent_cn, .. }
        | CertificateConfig::Client { parent_cn, .. } => {
            let parent_cn_dir = store_dir.join(parent_cn);
            let parent_key_pem = gpg::decrypt(parent_cn_dir.join(KEY_PEM_GPG))?;
            let parent_cert_pem = fs::read_to_string(parent_cn_dir.join(CERT_PEM))?;
            let parent_key_pair = KeyPair::from_pem(&parent_key_pem)?;
            let issuer = Issuer::from_ca_cert_pem(&parent_cert_pem, &parent_key_pair)?;
            params.signed_by(&key_pair, &issuer)?
        }
    };
    let cn_dir = store_dir.join(&cn);
    let cert_pem_file = cn_dir.join(CERT_PEM);
    let key_pem_gpg_file = cn_dir.join(KEY_PEM_GPG);
    if cert_pem_file.exists() {
        return Err(anyhow!("File already exists: {}", cert_pem_file.display()));
    }
    if key_pem_gpg_file.exists() {
        return Err(anyhow!(
            "File already exists: {}",
            key_pem_gpg_file.display()
        ));
    }
    fs::create_dir_all(&cn_dir)?;
    fs::write(&cert_pem_file, certificate.pem())?;
    let recipients = gpg::recipients(store_dir)?;
    gpg::encrypt(
        key_pair.serialize_pem().as_bytes(),
        &key_pem_gpg_file,
        recipients,
    )?;
    let commit_message = format!("Adding {kind} certificate {cn:?} to the store");
    git::add_and_commit(
        store_dir,
        [&key_pem_gpg_file, &cert_pem_file],
        &commit_message,
    )?;
    Ok(())
}

pub fn remove(store_dir: impl AsRef<Path>, name: &str) -> anyhow::Result<()> {
    let store_dir = store_dir.as_ref();
    let cn_dir = store_dir.join(name);
    let cert_pem_file = cn_dir.join(CERT_PEM);
    let key_pem_gpg_file = cn_dir.join(KEY_PEM_GPG);
    fs::remove_file(&cert_pem_file).ok_if_not_found()?;
    fs::remove_file(&key_pem_gpg_file).ok_if_not_found()?;
    fs::remove_dir(&cn_dir)?;
    git::remove_and_commit(
        store_dir,
        [&key_pem_gpg_file, &cert_pem_file],
        &format!("Removed {name:?} from the store"),
    )?;
    Ok(())
}

pub fn list(store_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    let store_dir = store_dir.as_ref();
    for entry in fs::read_dir(store_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let cn_dir = entry.path();
        let cert_pem_file = cn_dir.join(CERT_PEM);
        let key_pem_gpg_file = cn_dir.join(KEY_PEM_GPG);
        if cert_pem_file.exists() && key_pem_gpg_file.exists() {
            let cn = cn_dir.file_name().expect("File name exists").display();
            println!("{cn}");
        }
    }
    Ok(())
}

trait OkIfNotFound {
    fn ok_if_not_found(self) -> Self;
}

impl OkIfNotFound for std::io::Result<()> {
    fn ok_if_not_found(self) -> Self {
        match self {
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}
