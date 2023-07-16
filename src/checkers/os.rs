//! The OS checker.
//! This module contains the checker used to determine if the OS
//! can be identified.

use crate::models::{Finding, Technology};
use super::TcpChecker;
use regex::{Match, Regex};

/// The OS checker
pub struct OSChecker {
    /// The regex used to recognize the OS
    /// TODO: use an array of Regex
    regex: Regex
}

impl OSChecker {
    /// Creates a new OSChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: SSH-2.0-OpenSSH_6.7p1 Debian-5
        // Note: the -5 is actually ignored. Could be handled later.
        // TODO: get the package name & version when possible
        let regex = Regex::new(r"^SSH-\d+\.\d+-OpenSSH_\d+\.\d+([a-z]\d+)?( (?P<os>[a-zA-Z0-0]+))?").unwrap();
        OSChecker {
            regex: regex
        }
    }
}


impl TcpChecker for OSChecker {
    /// Check what OS is running on the asset.
    /// It looks for the OpenSSH banner.
    fn check(&self, data: &[String]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        // For each item, check if it's an OpenSSH banner
        for item in data {
            let caps_result = self.regex.captures(item);
            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                let os: Option<Match> = caps.name("os");

                // The OS has been found
                if os.is_some() {
                    let os_evidence_text = format!(
                        "The operating system {} has been identified using the banner presented by OpenSSH.",
                        os.unwrap().as_str()
                    );
                    let os_finding = Finding::new("OS", None, item, &os_evidence_text, None);
                    findings.push(os_finding);
                }
            }
        }
        return findings;
    }

    /// This checker supports the OS
    fn get_technology(&self) -> Technology {
        Technology::OS
    }
}
