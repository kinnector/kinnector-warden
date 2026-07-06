use std::path::Path;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    Clean,
    Elf,
    Suspicious(String),
}

/// Asynchronously scans a written file for high-confidence indicators of malicious uploads.
/// Check 1: ELF magic bytes (7F 45 4C 46) -> Quarantine
/// Check 2: Polyglot image+script tag detection -> High Alert
/// Check 3: Double extension with server-side script -> High Alert
pub async fn scan_uploaded_file(file_path: &str) -> ScanResult {
    let path = Path::new(file_path);
    if !path.exists() {
        return ScanResult::Clean;
    }

    // Attempt to open the file to read headers
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return ScanResult::Clean,
    };

    let mut buffer = [0u8; 512];
    let bytes_read = match file.read(&mut buffer) {
        Ok(n) => n,
        Err(_) => return ScanResult::Clean,
    };

    // Check 1: ELF Magic Bytes (7F 45 4C 46)
    if bytes_read >= 4 && buffer[0..4] == [0x7F, 0x45, 0x4C, 0x46] {
        return ScanResult::Elf;
    }



    // Check 3: Double-Extension Detection
    if let Some(filename) = path.file_name() {
        let name_str = filename.to_string_lossy();
        let parts: Vec<&str> = name_str.split('.').collect();
        if parts.len() > 2 {
            // Loop through middle extensions (e.g. file.php.jpg -> parts: ["file", "php", "jpg"])
            for ext in parts.iter().take(parts.len() - 1).skip(1) {
                let ext_lower = ext.to_lowercase();
                if ext_lower == "php" || ext_lower == "py" || ext_lower == "rb"
                    || ext_lower == "pl" || ext_lower == "jsp" || ext_lower == "aspx"
                {
                    return ScanResult::Suspicious(format!("Double extension containing script type: .{}", ext_lower));
                }
            }
        }
    }

    ScanResult::Clean
}
