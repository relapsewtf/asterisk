use std::fs;
// resources is a Resource table; goblin has limited helpers — do a lightweight scan for icon/manifest bytes
// We'll search the raw bytes for known icon and manifest markers as a pragmatic approach for a starter.
// RT_GROUP_ICON resource type numeric is 14, RT_MANIFEST is 24. In production, parse resource dirs precisely.


// simple heuristic: look for "RT_MANIFEST" (not present) so instead search for '<requestedExecutionLevel' XML snippet
if bytes.windows(20).any(|w| w == b"<requestedExecutionLevel") {
// naive: extract approximate value
if let Some(pos) = bytes.windows(50).position(|w| w.windows(22).any(|s| s == b"<requestedExecutionLevel")) {
// fallback: search for 'requireAdministrator' nearby
if bytes.windows(20).any(|w| w == b"requireAdministrator") {
req_exec = Some("requireAdministrator".to_string());
} else if bytes.windows(10).any(|w| w == b"highestAvailable") {
req_exec = Some("highestAvailable".to_string());
}
}
}
// Detect presence of ICON by simple marker search for icon headers: 'IDR_ICON' not reliable; search for PNG or ICO headers in resources area
if bytes.windows(4).any(|w| w == b"\x00\x00\x01\x00") || bytes.windows(8).any(|w| w == b"\x89PNG\r\n\x1a\n") {
has_icon = Some(true);
} else {
has_icon = Some(false);
}
}
(true, has_icon, req_exec)
}
Err(_) => (false, None, None),
}
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
if let Ok(bytes) = fs::read(path) {
let sha = sha256_hex(&bytes);
let ent = compute_entropy(&bytes);
let (is_pe, has_icon, req_exec) = check_pe_features(&bytes);
let rec = FileRecord {
path: path.display().to_string(),
sha256: sha,
entropy: ent,
is_pe,
has_icon,
requested_execution_level: req_exec,
};
results.push(rec);
}
}
}


let out = serde_json:z
}
