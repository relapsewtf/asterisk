use std::fs;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;
use sha2::{Digest, Sha256};
use serde::{Serialize, Deserialize};
use goblin::pe::PE;
use anyhow::Context;

#[derive(Serialize, Deserialize, Debug, Default)]
struct FileRecord {
    path: String,
    sha256: String,
    entropy: f64,
    is_pe: bool,
    has_icon: Option<bool>,
    requested_execution_level: Option<String>,
    signature: Option<SignatureInfo>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignatureInfo {
    // simple wrapper for starter: status string from PowerShell
    status: String,
    signer: Option<String>,
}

fn compute_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in bytes { counts[b as usize] += 1; }
    let n = bytes.len() as f64;
    if n == 0.0 { return 0.0; }
    let mut ent = 0.0;
    for &c in counts.iter() {
        if c == 0 { continue; }
        let p = (c as f64) / n;
        ent -= p * p.log2();
    }
    ent
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Check for PE properties: whether it's PE, whether it has icon resources, and manifest's requestedExecutionLevel
fn check_pe_features(bytes: &[u8]) -> (bool, Option<bool>, Option<String>) {
    match PE::parse(bytes) {
        Ok(_pe) => {
            let mut has_icon = None;
            let mut req_exec = None;

            // Heuristic search for manifest & icon resources in the raw bytes.
            // This is a pragmatic starter approach. A production version should parse the resource directory properly.

            // Search for '<requestedExecutionLevel' substring in bytes
            if bytes.windows(20).any(|w| w == b"<requestedExecutionLevel") {
                if bytes.windows(20).any(|w| w == b"requireAdministrator") {
                    req_exec = Some("requireAdministrator".to_string());
                } else if bytes.windows(20).any(|w| w == b"highestAvailable") {
                    req_exec = Some("highestAvailable".to_string());
                } else {
                    req_exec = Some("unknown".to_string());
                }
            }

            // Detect icon resources by looking for common ICO/Png headers inside resource area
            // ICO header starts with 0x00 0x00 0x01 0x00
            if bytes.windows(4).any(|w| w == [0x00,0x00,0x01,0x00]) || bytes.windows(8).any(|w| w == b"\x89PNG\r\n\x1a\n") {
                has_icon = Some(true);
            } else {
                has_icon = Some(false);
            }

            (true, has_icon, req_exec)
        }
        Err(_) => (false, None, None),
    }
}

/// Use PowerShell's Get-AuthenticodeSignature for a quick signature check.
/// Returns (status, signer) if PowerShell exists. This is a pragmatic approach for a starter.
fn check_signature_pwsh(path: &Path) -> Option<SignatureInfo> {
    // Check if powershell exists
    if which::which("powershell").is_err() && which::which("pwsh").is_err() {
        return None;
    }

    // Build powershell command to get signature status and signer
    let script = format!("$s = Get-AuthenticodeSignature -FilePath \\\"{}\\\"; if ($s -eq $null) {{ Write-Output \\\"NoSignature\\\"; }} else {{ Write-Output $s.Status; if ($s.SignerCertificate -ne $null) {{ Write-Output $s.SignerCertificate.Subject }} }}", path.display());

    let output = if which::which("pwsh").is_ok() {
        Command::new("pwsh").arg("-NoProfile").arg("-Command").arg(&script).output()
    } else {
        Command::new("powershell").arg("-NoProfile").arg("-Command").arg(&script).output()
    };

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).lines().map(|s| s.trim()).filter(|s| !s.is_empty()).collect::<Vec<_>>();
            if stdout.is_empty() {
                return None;
            }
            let status = stdout[0].to_string();
            let signer = if stdout.len() > 1 { Some(stdout[1].to_string()) } else { None };
            Some(SignatureInfo { status, signer })
        }
        Err(_) => None,
    }
}

fn process_file(path: &Path) -> anyhow::Result<FileRecord> {
    let bytes = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let sha = sha256_hex(&bytes);
    let ent = compute_entropy(&bytes);
    let (is_pe, has_icon, req_exec) = check_pe_features(&bytes);
    let signature = check_signature_pwsh(path);

    Ok(FileRecord { 
        path: path.display().to_string(),
        sha256: sha,
        entropy: ent,
        is_pe,
        has_icon,
        requested_execution_level: req_exec,
        signature,
    })
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: collector <scan-path>");
        std::process::exit(2);
    }
    let scan_path = &args[1];

    let mut results: Vec<FileRecord> = Vec::new();

    for entry in WalkDir::new(scan_path).follow_links(false).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            match process_file(path) {
                Ok(rec) => results.push(rec),
                Err(e) => eprintln!("Skipping {}: {}", path.display(), e),
            }
        }
    }

    let out = serde_json::to_string_pretty(&results)?;
    fs::write("findings.json", out)?;
    println!("Wrote findings.json with {} records", results.len());
    Ok(())
}
