//! The Exim checker.
//! This module contains the checker used to determine if Exim is
//! used by the asset.

use crate::models::Finding;
use super::TcpChecker;
use regex::Regex;

/// The Exim checker
pub struct EximChecker {
    /// The regex used to recognize Exim
    regex: Regex
}

impl EximChecker {
    /// Creates a new EximChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: 220 test.example.com ESMTP Exim 4.96 Mon, 10 Jul 2023 19:39:15 +0300
        // Date / time are ignored
        let regex = Regex::new(r"^\d\d\d ([a-zA-Z0-9-]+\.)?([a-zA-Z0-9-]+\.)?[a-zA-Z0-9-]+ (?P<smtpprotocol>E?SMTP) Exim (?P<eximversion>\d+\.\d+) ").unwrap();
        Self {
            regex: regex
        }
    }
}


impl TcpChecker for EximChecker {
    /// Check if the asset is running Exim.
    /// It looks for the Exim banner.
    fn check(&self, data: &[String]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        // For each item, check if it's an Exim banner
        for item in data {
            let caps_result = self.regex.captures(item);
            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                let exim_smtp_protocol: String = caps["smtpprotocol"].to_string();
                let exim_version: String = caps["eximversion"].to_string();
                let exim_evidence_text = format!(
                    "Exim {} has been identified running the {} protocol using the banner it presents after initiating a TCP connection: {}",
                    exim_version,
                    exim_smtp_protocol,
                    item
                );

                let exim_finding = Finding::new("Exim", Some(&exim_version), item, &exim_evidence_text);
                findings.push(exim_finding);
            }
        }
        return findings;
    }

}