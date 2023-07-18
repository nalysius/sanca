//! The OS checker.
//! This module contains the checker used to determine if the OS
//! can be identified.

use super::TcpChecker;
use crate::models::{Finding, Technology};
use regex::{Match, Regex};

/// The OS checker
pub struct OSChecker {
    /// The regex used to recognize the OS
    /// TODO: use an array of Regex
    regex: Regex,
}

impl OSChecker {
    /// Creates a new OSChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: SSH-2.0-OpenSSH_6.7p1 Debian-5
        // Note: the -5 is actually ignored. Could be handled later.
        // TODO: use the OpenSSH version & the OS name to determine which version
        // of OS is used
        let regex =
            Regex::new(r"^SSH-\d+\.\d+-OpenSSH_\d+\.\d+([a-z]\d+)?( (?P<os>[a-zA-Z0-0]+))?")
                .unwrap();
        OSChecker { regex: regex }
    }
}

impl TcpChecker for OSChecker {
    /// Check what OS is running on the asset.
    /// It looks for the OpenSSH banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
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
                    return Some(Finding::new("OS", None, item, &os_evidence_text, None));
                }
            }
        }
        return None;
    }

    /// This checker supports the OS
    fn get_technology(&self) -> Technology {
        Technology::OS
    }
}
