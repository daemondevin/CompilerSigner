// Code Signing Utility with Certificate Support + PKCS#12 export/import (OpenSSL) + SignTool wrapper
// Add the openssl crate to Cargo.toml with the "pkcs12" feature as shown above.

use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc, DateTime};
use clap::{Parser, Subcommand};
use der::{Decode, Encode};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    pss::{BlindedSigningKey, Signature, VerifyingKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use spki::SubjectPublicKeyInfoOwned;
use std::{
    fs,
    path::{Path, PathBuf},
    process,
    str::FromStr,
    time::SystemTime,
    env,
    process::Command,
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
    Certificate,
};

// OpenSSL imports
use openssl::pkcs12::Pkcs12;
use openssl::pkey::PKey;
use openssl::x509::X509;

#[derive(Parser)]
#[command(name = "CompilerSigner")]
#[command(about = "Code Signing Utility with Certificate Support", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "keys", global = true)]
    key_dir: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new RSA key pair
    GenerateKeys {
        #[arg(long, default_value_t = 2048)]
        bits: usize,
    },
    /// Generate a self-signed certificate for code signing
    GenerateCert {
        /// Common Name (e.g., "Your Name" or "Your Company")
        #[arg(long)]
        cn: String,
        /// Organization
        #[arg(long)]
        org: Option<String>,
        /// Country (2-letter code)
        #[arg(long)]
        country: Option<String>,
        /// Days until expiration
        #[arg(long, default_value_t = 365)]
        days: i64,
        /// Output format: pem, der, or pfx
        #[arg(long, default_value = "pem")]
        format: String,
        /// Password for PFX format (required if format is pfx)
        #[arg(long)]
        password: Option<String>,
    },
    /// Sign a file with certificate
    Sign {
        /// File to sign
        file: PathBuf,
        /// Use certificate-based signing (embed cert into .sig or used for SignTool)
        #[arg(long)]
        with_cert: bool,
        /// Path to specific certificate file (optional, defaults to certificate.pem/crt/cer in key directory)
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Hash algorithm: sha256 (default) or sha512
        #[arg(long, default_value = "sha256")]
        hash: String,
        /// Use SignTool (external Windows signtool.exe) for PE signing
        #[arg(long)]
        use_signtool: bool,
        /// Path to a .pfx/.p12 file (if you want to provide it directly to SignTool)
        #[arg(long)]
        pfx: Option<PathBuf>,
        /// Password for the PFX file (if required)
        #[arg(long)]
        pfx_password: Option<String>,
        /// Timestamp authority URL (RFC3161) to use with /tr
        #[arg(long)]
        timestamp_url: Option<String>,
        /// Timestamp digest algorithm: sha256 or sha512 (default sha256)
        #[arg(long, default_value = "sha256")]
        timestamp_digest: String,
    },
    /// Verify a file signature
    Verify {
        /// File to verify
        file: PathBuf,
        /// Hash algorithm to check against: sha256 (default) or sha512
        #[arg(long, default_value = "sha256")]
        hash: String,
    },
    /// Show certificate information
    ShowCert {
        /// Certificate file path (optional, defaults to certificate.pem/crt/cer in key directory)
        #[arg(long)]
        cert: Option<PathBuf>,
    },
    /// Export certificate to different format
    ExportCert {
        /// Output format: pem, der, cer, or pfx
        #[arg(long)]
        format: String,
        /// Output file path
        #[arg(long)]
        output: PathBuf,
        /// Password for PFX format (required if format is pfx)
        #[arg(long)]
        password: Option<String>,
    },
    /// Use Microsoft's SignTool.exe to sign Windows binaries
    SignTool {
        /// File to sign (.exe, .dll, etc.)
        file: PathBuf,

        /// Path to SignTool.exe (optional)
        #[arg(long)]
        signtool: Option<PathBuf>,

        /// Path to certificate (PFX)
        #[arg(long)]
        cert: PathBuf,

        /// Password for certificate
        #[arg(long)]
        password: String,

        /// Timestamp server URL
        #[arg(long)]
        timestamp: Option<String>,

        /// Hash algorithm (sha256 or sha512)
        #[arg(long, default_value = "sha256")]
        hash: String,

        /// Perform dual signing (sha256 + sha512)
        #[arg(long)]
        dual: bool,
    },

}

#[derive(Serialize, Deserialize)]
struct SignatureData {
    file: String,
    size: u64,
    sha256: Option<String>,
    sha512: Option<String>,
    hash_algorithm: String,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_valid_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_time: Option<String>,
}

struct CodeSigner {
    key_dir: PathBuf,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
    cert_path: PathBuf, // default certificate path (certificate.pem)
}

impl CodeSigner {
    fn new(key_dir: PathBuf) -> Self {
        let private_key_path = key_dir.join("private_key.pem");
        let public_key_path = key_dir.join("public_key.pem");
        let cert_path = key_dir.join("certificate.pem"); // default; we also accept .crt/.cer

        Self {
            key_dir,
            private_key_path,
            public_key_path,
            cert_path,
        }
    }

    fn candidate_cert_paths(&self) -> Vec<PathBuf> {
        vec![
            self.key_dir.join("certificate.pem"),
            self.key_dir.join("certificate.crt"),
            self.key_dir.join("certificate.cer"),
        ]
    }

    fn generate_keys(&self, bits: usize) -> Result<(), Box<dyn std::error::Error>> {
        println!("Generating {}-bit RSA key pair...", bits);

        fs::create_dir_all(&self.key_dir)?;

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let public_key = RsaPublicKey::from(&private_key);

        // Save private key
        private_key.write_pkcs8_pem_file(&self.private_key_path, LineEnding::LF)?;

        // Save public key
        public_key.write_public_key_pem_file(&self.public_key_path, LineEnding::LF)?;

        println!("✓ Keys generated successfully");
        println!("  Private key: {}", self.private_key_path.display());
        println!("  Public key: {}", self.public_key_path.display());

        Ok(())
    }

    fn generate_certificate(
        &self,
        cn: &str,
        org: Option<&str>,
        country: Option<&str>,
        days: i64,
        format: &str,
        password: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.private_key_path.exists() {
            eprintln!("Error: Private key not found. Generate keys first with: generate-keys");
            process::exit(1);
        }

        if days < 1 {
            return Err("Days must be positive".into());
        }

        println!("Generating self-signed certificate...");

        let private_key = self.load_private_key()?;
        let public_key = RsaPublicKey::from(&private_key);

        // Build subject/issuer name
        let mut subject_parts = vec![format!("CN={}", cn)];
        if let Some(o) = org {
            subject_parts.push(format!("O={}", o));
        }
        if let Some(c) = country {
            subject_parts.push(format!("C={}", c));
        }
        let subject_str = subject_parts.join(",");
        let subject = Name::from_str(&subject_str)?;

        // Generate serial number
        let serial_num: u64 = rand::random();
        let serial = SerialNumber::from(serial_num);

        // Set validity period
        let not_before = Utc::now();
        let not_after = not_before + Duration::days(days);
        let validity = Validity::from_now(std::time::Duration::from_secs((days * 86400) as u64))?;

        // Convert public key to SPKI
        let spki = SubjectPublicKeyInfoOwned::from_key(public_key)?;

        // Create signing key for certificate generation (PKCS#1 v1.5)
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);

        // Build certificate
        let builder = CertificateBuilder::new(
            Profile::Root,
            serial,
            validity,
            subject.clone(),
            spki,
            &signing_key,
        )?;

        let cert = builder.build::<rsa::pkcs1v15::Signature>()?;

        // Save certificate in PEM format
        let cert_der = cert.to_der()?;
        let cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            general_purpose::STANDARD.encode(&cert_der)
        );
        fs::write(&self.cert_path, cert_pem)?;

        println!("✓ Certificate generated successfully");
        println!("  Certificate: {}", self.cert_path.display());
        println!("  Subject: {}", subject_str);
        println!("  Valid from: {}", not_before.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("  Valid to: {}", not_after.format("%Y-%m-%d %H:%M:%S UTC"));

        // If user requested pfx format, create it
        if format.eq_ignore_ascii_case("pfx") || format.eq_ignore_ascii_case("p12") {
            if password.is_none() {
                eprintln!("Warning: PFX export requested but no password provided. Creating PFX with empty password.");
            }
            let out = self.key_dir.join("certificate.pfx");
            self.export_pfx_using_openssl(&out, password)?;
            println!("  PFX written to: {}", out.display());
        }

        Ok(())
    }

    fn load_private_key(&self) -> Result<RsaPrivateKey, Box<dyn std::error::Error>> {
        let key = RsaPrivateKey::read_pkcs8_pem_file(&self.private_key_path)?;
        Ok(key)
    }

    fn load_public_key(&self) -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
        let key = RsaPublicKey::read_public_key_pem_file(&self.public_key_path)?;
        Ok(key)
    }

    /// Try to load a certificate from the given path
    fn load_certificate_from_path(&self, path: &Path) -> Result<Certificate, Box<dyn std::error::Error>> {
        let file_data = fs::read(path)?;
        
        // Try to detect format
        if file_data.starts_with(b"-----BEGIN CERTIFICATE-----") {
            // PEM format
            let pem_str = String::from_utf8(file_data)?;
            let cert_b64: String = pem_str
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            let cert_der = general_purpose::STANDARD.decode(cert_b64)?;
            Ok(Certificate::from_der(&cert_der)?)
        } else {
            // Assume DER/CER format
            Ok(Certificate::from_der(&file_data)?)
        }
    }

    /// Attempt to load a certificate from the default candidate locations (pem, crt, cer)
    fn load_certificate(&self) -> Result<Certificate, Box<dyn std::error::Error>> {
        for p in self.candidate_cert_paths() {
            if p.exists() {
                return self.load_certificate_from_path(&p);
            }
        }
        Err(format!("No certificate found in key dir (tried .pem .crt .cer)").into())
    }

    /// Helper: try to convert x509 `Time` to chrono DateTime<Utc>.
    fn cert_time_to_datetime<T>(&self, time: &T) -> Result<DateTime<Utc>, Box<dyn std::error::Error>>
    where
        T: std::fmt::Display,
    {
        let s = format!("{}", time);
        if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
            return Ok(dt.with_timezone(&Utc));
        }
        if let Ok(dt) = DateTime::parse_from_rfc2822(&s) {
            return Ok(dt.with_timezone(&Utc));
        }
        if let Ok(dt) = DateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S %Z") {
            return Ok(dt.with_timezone(&Utc));
        }
        Err(format!("Unable to parse certificate time: {}", s).into())
    }

    /// Export a PFX (PKCS#12) using OpenSSL crate. This writes private key + single certificate (no chain).
    fn export_pfx_using_openssl(&self, output: &Path, password: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
        // Load certificate (DER) and private key (PKCS#8 DER)
        let cert = self.load_certificate()?;
        let cert_der = cert.to_der()?;
        let priv_key = self.load_private_key()?;
        let priv_der = priv_key.to_pkcs8_der()?.as_bytes().to_vec();

        // Convert to OpenSSL types
        let pkey = PKey::private_key_from_der(&priv_der)?;
        let x509 = X509::from_der(&cert_der)?;

        let pwd = password.unwrap_or("");
        let builder = Pkcs12::builder();
        let p12 = builder.build(pwd, "codesign", &pkey, &x509)?;
        let der = p12.to_der()?;
        fs::write(output, &der)?;

        Ok(())
    }
        fn find_signtool(&self, user_path: Option<&Path>) -> Option<PathBuf> {
        if let Some(p) = user_path {
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }

        // Try PATH
        if let Ok(output) = which::which("signtool.exe") {
            return Some(output);
        }

        // Try common Windows SDK locations
        let program_files = std::env::var("ProgramFiles(x86)").unwrap_or_default();
        let sdk_paths = vec![
            format!("{program_files}\\Windows Kits\\10\\bin\\x64\\signtool.exe"),
            format!("{program_files}\\Windows Kits\\10\\bin\\x86\\signtool.exe"),
            format!("{program_files}\\Windows Kits\\8.1\\bin\\x64\\signtool.exe"),
        ];
        for p in sdk_paths {
            let path = PathBuf::from(p);
            if path.exists() {
                return Some(path);
            }
        }

        None
    }

    fn sign_with_signtool(
        &self,
        file: &Path,
        signtool_path: Option<&Path>,
        cert_path: &Path,
        password: &str,
        timestamp: Option<&str>,
        hash: &str,
        dual: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signtool = self.find_signtool(signtool_path).ok_or_else(|| {
            "SignTool.exe not found. Please install the Windows SDK or specify --signtool <path>"
        })?;

        println!("Using SignTool at: {}", signtool.display());
        println!("Signing file: {}", file.display());

        // Build base command
        let mut cmd = Command::new(&&signtool);
        cmd.arg("sign")
            .arg("/f").arg(cert_path)
            .arg("/p").arg(password)
            .arg("/fd").arg(hash)
            .arg("/tr").arg(timestamp.unwrap_or("http://timestamp.digicert.com"))
            .arg("/td").arg(hash)
            .arg("/v")
            .arg(file);

        let status = cmd.status()?;

        if !status.success() {
            eprintln!("✗ SignTool failed. Exit code: {:?}", status.code());
            process::exit(1);
        }

        println!("✓ Signed successfully with {}", hash);

        if dual {
            println!("Performing dual-signing with SHA512...");

            let mut dual_cmd = Command::new(signtool);
            dual_cmd
                .arg("sign")
                .arg("/as") // append secondary signature
                .arg("/f").arg(cert_path)
                .arg("/p").arg(password)
                .arg("/fd").arg("sha512")
                .arg("/tr").arg(timestamp.unwrap_or("http://timestamp.digicert.com"))
                .arg("/td").arg("sha512")
                .arg("/v")
                .arg(file);

            let dual_status = dual_cmd.status()?;
            if !dual_status.success() {
                eprintln!("✗ Dual-signing failed. Exit code: {:?}", dual_status.code());
                process::exit(1);
            }

            println!("✓ Dual-signed successfully (SHA256 + SHA512)");
        }

        Ok(())
    }
    /// Call signtool.exe with the provided options. Returns true on success.
    fn call_signtool(
        &self,
        file_path: &Path,
        pfx_path: &Path,
        pfx_password: Option<&str>,
        file_hash_alg: &str,
        timestamp_url: Option<&str>,
        timestamp_digest: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        // Build arguments for signtool
        // Example:
        // signtool sign /f cert.pfx /p password /fd sha256 /tr http://tsa.url /td sha256 <file>
        let mut args: Vec<String> = Vec::new();
        args.push("sign".into());
        args.push("/f".into());
        args.push(pfx_path.to_string_lossy().into_owned());
        if let Some(pwd) = pfx_password {
            if !pwd.is_empty() {
                args.push("/p".into());
                args.push(pwd.into());
            }
        }
        // file digest algorithm
        args.push("/fd".into());
        args.push(file_hash_alg.to_lowercase());

        // Timestamp: prefer RFC3161 (/tr + /td)
        if let Some(turl) = timestamp_url {
            args.push("/tr".into());
            args.push(turl.into());
            args.push("/td".into());
            args.push(timestamp_digest.to_lowercase());
        }

        // Add file path
        args.push(file_path.to_string_lossy().into_owned());

        // On Windows, the binary is usually "signtool.exe" provided by Windows SDK.
        // We will attempt to run "signtool" (allow user to have it in PATH).
        let exe_name = if cfg!(windows) { "signtool.exe" } else { "signtool" };

        println!("Calling SignTool: {} {}", exe_name, args.join(" "));
        let status = Command::new(exe_name)
            .args(&args)
            .status();

        match status {
            Ok(s) => {
                if s.success() {
                    println!("✓ SignTool succeeded");
                    Ok(true)
                } else {
                    println!("✗ SignTool failed with exit code: {:?}", s.code());
                    Ok(false)
                }
            }
            Err(e) => {
                eprintln!("Error running SignTool: {}", e);
                Err(format!("Failed to launch SignTool (is it installed and in PATH?)").into())
            }
        }
    }

    fn sign_file(&self, file_path: &Path, with_cert: bool, cert_path: Option<&Path>, hash_alg: &str, use_signtool: bool, pfx: Option<&Path>, pfx_password: Option<&str>, timestamp_url: Option<&str>, timestamp_digest: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !file_path.exists() {
            eprintln!("Error: File not found: {}", file_path.display());
            process::exit(1);
        }

        if !self.private_key_path.exists() {
            eprintln!("Error: Private key not found. Generate keys first with: generate-keys");
            process::exit(1);
        }

        // Determine certificate path to use (if any)
        let cert_to_use = cert_path.map(|p| p.to_path_buf()).or_else(|| {
            for p in self.candidate_cert_paths() {
                if p.exists() {
                    return Some(p);
                }
            }
            None
        });

        if with_cert && cert_to_use.is_none() && pfx.is_none() && !use_signtool {
            eprintln!("Error: Certificate not found in key directory (looked for certificate.pem/crt/cer).");
            eprintln!("Generate one with: generate-cert --cn \"Your Name\"");
            process::exit(1);
        }

        println!("Signing {}...", file_path.display());
        if with_cert {
            if let Some(ref p) = cert_to_use { println!("  Using certificate: {}", p.display()); }
        }

        // If user requests use_signtool and file looks like PE, call SignTool
        if use_signtool {
            // Only proceed for PE types (.exe, .dll)
            if let Some(ext) = file_path.extension().and_then(|s| s.to_str()) {
                let ext_low = ext.to_ascii_lowercase();
                if ext_low == "exe" || ext_low == "dll" {
                    // Determine PFX to give to SignTool: explicit pfx path, or export a temp pfx
                    let mut temp_pfx_path: Option<PathBuf> = None;
                    let pfx_to_use: PathBuf = if let Some(pfx_path) = pfx {
                        pfx_path.to_path_buf()
                    } else {
                        // Export a temporary PFX to temp dir
                        let tmpdir = env::temp_dir();
                        // create unique name with timestamp + pid
                        let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
                        let pid = std::process::id();
                        let tmp = tmpdir.join(format!("codesign_temp_{}_{}.pfx", pid, ts));
                        // export; allow empty password if none provided
                        self.export_pfx_using_openssl(&tmp, pfx_password)?;
                        temp_pfx_path = Some(tmp.clone());
                        tmp
                    };

                    // Call SignTool
                    match self.call_signtool(file_path, &pfx_to_use, pfx_password, hash_alg, timestamp_url, timestamp_digest) {
                        Ok(true) => {
                            // cleanup temp pfx if created
                            if let Some(t) = temp_pfx_path {
                                let _ = fs::remove_file(t);
                            }
                            println!("✓ File signed using SignTool");
                            return Ok(());
                        }
                        Ok(false) => {
                            if let Some(t) = temp_pfx_path { let _ = fs::remove_file(t); }
                            eprintln!("SignTool reported failure.");
                            process::exit(1);
                        }
                        Err(e) => {
                            if let Some(t) = temp_pfx_path { let _ = fs::remove_file(t); }
                            return Err(e);
                        }
                    }
                } else {
                    eprintln!("--use-signtool requested but file is not a PE (.exe/.dll). Falling back to detached signature.");
                }
            }
        }

        // --- fallback: previous behavior (detached JSON .sig) ---

        // Read file and compute hash(s)
        let file_data = fs::read(file_path)?;
        let mut hasher256 = Sha256::new();
        hasher256.update(&file_data);
        let file_hash256 = hasher256.finalize();

        let mut file_hash512 = Vec::new();
        if hash_alg.eq_ignore_ascii_case("sha512") {
            let mut hasher512 = Sha512::new();
            hasher512.update(&file_data);
            file_hash512 = hasher512.finalize().to_vec();
        }

        // Sign the chosen hash
        let private_key = self.load_private_key()?;

        let signature_bytes = if hash_alg.eq_ignore_ascii_case("sha512") {
            let signing_key = BlindedSigningKey::<Sha512>::new(private_key);
            let mut rng = rand::thread_rng();
            let sig: rsa::pss::Signature = signing_key.sign_with_rng(&mut rng, &file_hash512);
            sig.to_bytes().to_vec()
        } else {
            // default sha256
            let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
            let mut rng = rand::thread_rng();
            let sig: rsa::pss::Signature = signing_key.sign_with_rng(&mut rng, &file_hash256);
            sig.to_bytes().to_vec()
        };

        // Create signature data
        let mut sig_data = SignatureData {
            file: file_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            size: file_data.len() as u64,
            sha256: Some(general_purpose::STANDARD.encode(&file_hash256[..])),
            sha512: if file_hash512.is_empty() { None } else { Some(general_purpose::STANDARD.encode(&file_hash512)) },
            hash_algorithm: hash_alg.to_lowercase(),
            signature: general_purpose::STANDARD.encode(&signature_bytes),
            certificate: None,
            cert_subject: None,
            cert_issuer: None,
            cert_valid_from: None,
            cert_valid_to: None,
            signing_time: Some(Utc::now().to_rfc3339()),
        };

        // Add certificate info if requested
        if with_cert {
            let cert_path = cert_to_use.as_ref().unwrap();
            let cert = self.load_certificate_from_path(cert_path)?;
            let cert_der = cert.to_der()?;
            sig_data.certificate = Some(general_purpose::STANDARD.encode(&cert_der));
            sig_data.cert_subject = Some(cert.tbs_certificate.subject.to_string());
            sig_data.cert_issuer = Some(cert.tbs_certificate.issuer.to_string());
            sig_data.cert_valid_from = Some(cert.tbs_certificate.validity.not_before.to_string());
            sig_data.cert_valid_to = Some(cert.tbs_certificate.validity.not_after.to_string());
        }

        let sig_path = file_path.with_extension(
            format!(
                "{}.sig",
                file_path.extension().unwrap_or_default().to_string_lossy()
            )
        );

        let sig_json = serde_json::to_string_pretty(&sig_data)?;
        fs::write(&sig_path, sig_json)?;

        println!("✓ Signature created: {}", sig_path.display());

        Ok(())
    }

    fn verify_file(&self, file_path: &Path, hash_alg: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let sig_path = file_path.with_extension(
            format!(
                "{}.sig",
                file_path.extension().unwrap_or_default().to_string_lossy()
            )
        );

        if !file_path.exists() {
            eprintln!("Error: File not found: {}", file_path.display());
            return Ok(false);
        }

        if !sig_path.exists() {
            eprintln!("Error: Signature file not found: {}", sig_path.display());
            return Ok(false);
        }

        println!("Verifying {}...", file_path.display());

        // Load signature data
        let sig_json = fs::read_to_string(&sig_path)?;
        let sig_data: SignatureData = serde_json::from_str(&sig_json)?;

        // Read and hash file
        let file_data = fs::read(file_path)?;
        let mut hasher256 = Sha256::new();
        hasher256.update(&file_data);
        let file_hash256 = hasher256.finalize();

        let mut file_hash512 = Vec::new();
        if hash_alg.eq_ignore_ascii_case("sha512") {
            let mut hasher512 = Sha512::new();
            hasher512.update(&file_data);
            file_hash512 = hasher512.finalize().to_vec();
        }

        // Check recorded hash matches actual
        let expected_hash = match sig_data.hash_algorithm.as_str() {
            "sha512" => {
                if let Some(h) = &sig_data.sha512 {
                    general_purpose::STANDARD.decode(h)?
                } else {
                    eprintln!("Signature claims sha512 but signature file has no sha512 field");
                    return Ok(false);
                }
            }
            _ => {
                if let Some(h) = &sig_data.sha256 {
                    general_purpose::STANDARD.decode(h)?
                } else {
                    eprintln!("Signature claims sha256 but signature file has no sha256 field");
                    return Ok(false);
                }
            }
        };

        let actual_hash_bytes = if sig_data.hash_algorithm.eq("sha512") {
            file_hash512.clone()
        } else {
            file_hash256.to_vec()
        };

        if expected_hash != actual_hash_bytes {
            println!("✗ Verification FAILED: File hash does not match (file was modified or wrong hash algorithm)");
            return Ok(false);
        }

        // Get public key (from certificate if present, otherwise from key file)
        let public_key = if let Some(cert_b64) = &sig_data.certificate {
            println!("  Certificate found in signature");
            let cert_der = general_purpose::STANDARD.decode(cert_b64)?;
            let cert = Certificate::from_der(&cert_der)?;

            // Display certificate info
            if let Some(subject) = &sig_data.cert_subject {
                println!("  Signed by: {}", subject);
            }
            if let (Some(from), Some(to)) = (&sig_data.cert_valid_from, &sig_data.cert_valid_to) {
                println!("  Valid: {} to {}", from, to);
            }

            // Check certificate validity now
            let not_before = &cert.tbs_certificate.validity.not_before;
            let not_after = &cert.tbs_certificate.validity.not_after;
            match (self.cert_time_to_datetime(not_before), self.cert_time_to_datetime(not_after)) {
                (Ok(nb), Ok(na)) => {
                    let now = Utc::now();
                    if now < nb {
                        println!("✗ Certificate is NOT YET VALID (valid from {})", nb);
                        return Ok(false);
                    }
                    if now > na {
                        println!("✗ Certificate is EXPIRED (valid to {})", na);
                        return Ok(false);
                    }
                }
                (Err(e1), _) | (_, Err(e1)) => {
                    println!("Warning: could not parse certificate validity times: {}", e1);
                    println!("Refusing to verify with un-parseable validity range (safe default).");
                    return Ok(false);
                }
            }

            // Extract public key from certificate
            let spki = &cert.tbs_certificate.subject_public_key_info;
            let spki_der = spki.to_der()?;
            RsaPublicKey::from_public_key_der(&spki_der)?
        } else {
            // No certificate embedded: try to load default certificate files in key dir (.pem/.crt/.cer) first
            if let Ok(cert) = self.load_certificate() {
                println!("  Using certificate from key directory ({})", self.key_dir.display());
                // As above, check validity
                let not_before = &cert.tbs_certificate.validity.not_before;
                let not_after = &cert.tbs_certificate.validity.not_after;
                match (self.cert_time_to_datetime(not_before), self.cert_time_to_datetime(not_after)) {
                    (Ok(nb), Ok(na)) => {
                        let now = Utc::now();
                        if now < nb {
                            println!("✗ Certificate is NOT YET VALID (valid from {})", nb);
                            return Ok(false);
                        }
                        if now > na {
                            println!("✗ Certificate is EXPIRED (valid to {})", na);
                            return Ok(false);
                        }
                    }
                    (Err(e1), _) | (_, Err(e1)) => {
                        println!("Warning: could not parse certificate validity times: {}", e1);
                        println!("Refusing to verify with un-parseable validity range (safe default).");
                        return Ok(false);
                    }
                }

                let spki = &cert.tbs_certificate.subject_public_key_info;
                let spki_der = spki.to_der()?;
                RsaPublicKey::from_public_key_der(&spki_der)?
            } else {
                // Fallback to public_key.pem
                if !self.public_key_path.exists() {
                    eprintln!("Error: Public key not found");
                    return Ok(false);
                }
                self.load_public_key()?
            }
        };

        // Verify signature
        let verifying_result = {
            let signature_bytes = general_purpose::STANDARD.decode(&sig_data.signature)?;
            let signature = Signature::try_from(signature_bytes.as_slice())?;
            if sig_data.hash_algorithm.eq("sha512") {
                let verifying_key = VerifyingKey::<Sha512>::new(public_key);
                verifying_key.verify(&actual_hash_bytes, &signature)
            } else {
                let verifying_key = VerifyingKey::<Sha256>::new(public_key);
                verifying_key.verify(&actual_hash_bytes, &signature)
            }
        };

        match verifying_result {
            Ok(_) => {
                println!("✓ Signature is VALID");
                Ok(true)
            }
            Err(_) => {
                println!("✗ Signature verification FAILED");
                Ok(false)
            }
        }
    }

    fn show_certificate(&self, cert_path: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
        // if cert_path unspecified, attempt to find certificate.pem/crt/cer in key_dir
        let path = if let Some(p) = cert_path {
            p.to_path_buf()
        } else {
            let mut found = None;
            for p in self.candidate_cert_paths() {
                if p.exists() {
                    found = Some(p);
                    break;
                }
            }
            if found.is_none() {
                eprintln!("Error: Certificate not found in key directory (tried pem/crt/cer).");
                eprintln!("Generate one with: generate-cert --cn \"Your Name\"");
                process::exit(1);
            }
            found.unwrap()
        };

        if !path.exists() {
            eprintln!("Error: Certificate not found at {}", path.display());
            eprintln!("Generate one with: generate-cert --cn \"Your Name\"");
            process::exit(1);
        }

        let cert = self.load_certificate_from_path(&path)?;

        println!("Certificate Information:");
        println!("  Subject: {}", cert.tbs_certificate.subject);
        println!("  Issuer: {}", cert.tbs_certificate.issuer);
        println!("  Serial: {:?}", cert.tbs_certificate.serial_number);
        println!("  Valid From: {}", cert.tbs_certificate.validity.not_before);
        println!("  Valid To: {}", cert.tbs_certificate.validity.not_after);
        println!("  Location: {}", path.display());

        Ok(())
    }

    fn export_certificate(
        &self,
        format: &str,
        output: &Path,
        password: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Prefer to find any certificate in the key dir
        let cert = self.load_certificate()?;
        let cert_der = cert.to_der()?;

        match format.to_lowercase().as_str() {
            "pem" => {
                let cert_pem = format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    general_purpose::STANDARD.encode(&cert_der)
                );
                fs::write(output, cert_pem)?;
                println!("✓ Certificate exported to {} (PEM format)", output.display());
            }
            "der" | "cer" => {
                fs::write(output, cert_der)?;
                println!("✓ Certificate exported to {} (DER/CER format)", output.display());
            }
            "pfx" | "p12" => {
                let pwd = password.unwrap_or("");
                self.export_pfx_using_openssl(output, Some(pwd))?;
                println!("✓ Certificate + private key exported to {} (PFX format)", output.display());
            }
            _ => {
                eprintln!("Error: Unsupported format '{}'. Use: pem, der, cer, or pfx", format);
                process::exit(1);
            }
        }

        Ok(())
    }
}

fn main() {
    let cli = Cli::parse();
    let signer = CodeSigner::new(cli.key_dir);

    let result = match cli.command {
        Commands::GenerateKeys { bits } => signer.generate_keys(bits),
        Commands::GenerateCert { cn, org, country, days, format, password } => {
            signer.generate_certificate(&cn, org.as_deref(), country.as_deref(), days, &format, password.as_deref())
        }
        Commands::Sign { file, with_cert, cert, hash, use_signtool, pfx, pfx_password, timestamp_url, timestamp_digest } => {
            signer.sign_file(&file, with_cert, cert.as_deref(), &hash, use_signtool, pfx.as_deref(), pfx_password.as_deref(), timestamp_url.as_deref(), &timestamp_digest)
        }
        Commands::SignTool { file, signtool, cert, password, timestamp, hash, dual } => {
            signer.sign_with_signtool(&file, signtool.as_deref(), &cert, &password, timestamp.as_deref(), &hash, dual)
        }
        Commands::Verify { file, hash } => signer.verify_file(&file, &hash).map(|_| ()),
        Commands::ShowCert { cert } => signer.show_certificate(cert.as_deref()),
        Commands::ExportCert { format, output, password } => {
            signer.export_certificate(&format, &output, password.as_deref())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
