//! The OpenSSH checker.
//! This module contains the checker used to determine if OpenSSH is
//! used by the asset.

use crate::models::{Finding, ScanType};
use super::Checker;
use regex::{Match, Regex};

/// The OpenSSH checker
pub struct OpenSSHChecker {
    /// The regex used to recognize OpenSSH
    regex: Regex
}

impl OpenSSHChecker {
    /// Creates a new OpenSSHChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: SSH-2.0-OpenSSH_6.7p1 Debian-5
        // Note: the -5 is actually ignored. Could be handled later.
        // TODO: get the package name & version when possible
        let regex = Regex::new(r"^SSH-(?P<sshversion>\d+\.\d+)-OpenSSH_(?P<opensshversion>\d+\.\d+([a-z]\d+)?)( (?P<os>[a-zA-Z0-0]+))?").unwrap();
        OpenSSHChecker {
            regex: regex
        }
    }
}


impl Checker for OpenSSHChecker {
    /// Check if the asset is running OpenSSH.
    /// It looks for the OpenSSH banner. It can create two findings,
    /// one for OpenSSH and one for the OS if present.
    fn check(&self, data: &[String]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        // For each item, check if it's an OpenSSH banner
        for item in data {
            let caps_result = self.regex.captures(item);
            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                //let ssh_version: String = caps["sshversion"].to_string();
                let openssh_version: String = caps["opensshversion"].to_string();
                let os: Option<Match> = caps.name("os");
                let openssh_evidence_text = format!(
                    "OpenSSH {} has been identified using the banner it presents after initiating a TCP connection: {}"
                    ,
                    openssh_version,
                    item
                );

                let openssh_finding = Finding::new("OpenSSH", Some(&openssh_version), item, &openssh_evidence_text);
                findings.push(openssh_finding);

                // The OS has been found
                if os.is_some() {
                    let os_evidence_text = format!(
                        "The operating system {} has been identified using the banner presented by OpenSSH.",
                        os.unwrap().as_str()
                    );
                    let os_finding = Finding::new("OS", None, item, &os_evidence_text);
                    findings.push(os_finding);
                }
            }
        }
        return findings;
    }

    fn get_scan_types(&self) -> Vec<ScanType> {
        vec![ScanType::Tcp]
    }
}