//! The ProFTPD checker.
//! This module contains the checker used to determine if ProFTPd is
//! used by the asset.

use crate::models::Finding;
use super::TcpChecker;
use regex::Regex;

/// The ProFTPD checker
pub struct ProFTPDChecker {
    /// The regex used to recognize ProFTPD
    regex: Regex
}

impl ProFTPDChecker {
    /// Creates a new ProFTPDChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: 220 ProFTPD 1.3.5b Server (ProFTPD) [11.22.33.44]
        // The IP address is ignored by the regex
        let regex = Regex::new(r"^\d\d\d ProFTPD (?P<proftpdversion>\d+\.\d+\.\d+[a-z]?) Server \((?P<proftpdname>.+)\)").unwrap();
        Self {
            regex: regex
        }
    }
}


impl TcpChecker for ProFTPDChecker {
    /// Check if the asset is running ProFTPD.
    /// It looks for the ProFTPD banner.
    fn check(&self, data: &[String]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        // For each item, check if it's an ProFTPD banner
        for item in data {
            let caps_result = self.regex.captures(item);
            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                let proftpd_version: String = caps["proftpdversion"].to_string();
                let proftpd_name: String = caps["proftpdname"].to_string();
                let proftpd_evidence_text = format!(
                    "ProFTPD {} has been found under the name \"{}\" using the banner it presents after initiating a TCP connection: {}",
                    proftpd_version,
                    proftpd_name,
                    item
                );

                let proftpd_finding = Finding::new("ProFTPD", Some(&proftpd_version), item, &proftpd_evidence_text);
                findings.push(proftpd_finding);
            }
        }
        return findings;
}

}