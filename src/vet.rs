/// Detects SQL Injection (SQLi) patterns in request payloads or query strings.
pub fn check_sqli(input: &str) -> bool {
    let input_lower = input.to_lowercase();

    // Key SQLi patterns & token transitions
    let signatures = [
        "union select",
        "union all select",
        "drop table",
        "information_schema",
        "schema_name",
        "table_schema",
        "table_name",
        "column_name",
        "group_concat",
        "load_file",
        "into outfile",
        "benchmark(",
        "pg_sleep(",
        "dbms_pipe.receive_message",
        "' or '1'='1",
        "' or 1=1",
        "\" or \"1\"=\"1",
        "\" or 1=1",
        "' or ''='",
        "\" or \"\"=\"",
        "or 'a'='a",
        "or true",
        "or 1 == 1",
        "or 1=1",
        "or '1'='1",
        "select current_user",
        "select user()",
        "select database()",
        "select version()",
    ];

    for sig in &signatures {
        if input_lower.contains(sig) {
            return true;
        }
    }

    // Check for comment characters which are common injection markers
    if input_lower.contains("/*") || input_lower.contains("--") {
        return true;
    }

    // Check for hash comment sign (#) outside of HTML entities (like &#123;)
    if input_lower.contains('#') && !input_lower.contains("&#") {
        return true;
    }

    false
}

/// Detects Command Injection (CMD-i) patterns in request parameters.
pub fn check_cmdi(input: &str) -> bool {
    let input_lower = input.to_lowercase();

    // Command injection indicators (pipe/redirect chars followed by command names)
    let command_patterns = [
        "rm ",
        "curl",
        "wget",
        "whoami",
        "id",
        "uname",
        "cat ",
    ];

    let prefixes = [";", "|", "&", "&&", "||"];

    for prefix in &prefixes {
        for pattern in &command_patterns {
            let signature1 = format!("{}{}", prefix, pattern);
            let signature2 = format!("{} {}", prefix, pattern);
            if input_lower.contains(&signature1) || input_lower.contains(&signature2) {
                return true;
            }
        }
    }

    // Common system command executions and paths
    let general_signatures = [
        "/bin/sh",
        "/bin/bash",
        "/bin/dash",
        "/bin/zsh",
        "/bin/ash",
        "cmd.exe",
        "powershell.exe",
        "etc/passwd",
        "etc/shadow",
        "eval(base64_decode",
        "system(",
        "exec(",
        "passthru(",
        "shell_exec(",
    ];

    for sig in &general_signatures {
        if input_lower.contains(sig) {
            return true;
        }
    }

    false
}

/// Combines SQLi and CMD-i vetting.
pub fn vet_string(input: &str) -> bool {
    check_sqli(input) || check_cmdi(input)
}
