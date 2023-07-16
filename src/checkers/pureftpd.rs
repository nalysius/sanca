//! The Pure-FTPd checker.
//! This module contains the checker used to determine if Pure-FTPd is
//! used by the asset.

use crate::models::{Finding, Technology};
use super::TcpChecker;
use regex::Regex;

/// The Pure-FTPd checker
pub struct PureFTPdChecker {
    /// The regex used to recognize Pure-FTPd
    regex: Regex
}

impl PureFTPdChecker {
    /// Creates a new PureFTPdChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: 220---------- Welcome to Pure-FTPd [name] [TLS] ----------
        let regex = Regex::new(r"Welcome to Pure-FTPd \[(?P<srvname>[a-zA-z0-9-_.]+)\]").unwrap();
        Self {
            regex: regex
        }
    }
}


impl TcpChecker for PureFTPdChecker {
    /// Check if the asset is running Pure-FTPd.
    /// It looks for the Pure-FTPd banner.
    fn check(&self, data: &[String]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        // For each item, check if it's an Pure-FTPd banner
        for item in data {
            let caps_result = self.regex.captures(item);
            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                let srvname: String = caps["srvname"].to_string();
                // The banner can be several line long, so truncate it and take only the first one
                let mut evidence = item[0..item.find("\r\n").unwrap_or(item.len() - 1)].to_string();
                // If the banner has been trucated, say it
                if evidence.len() < item.len() {
                    evidence.push_str("[truncated]");
                }
                let evidence_text = format!(
                    "Pure-FTPd has been found under the name \"{}\" using the banner it presents after initiating a TCP connection: {}",
                    srvname,
                    evidence
                );

                let finding = Finding::new("Pure-FTPd", None, &evidence, &evidence_text, None);
                findings.push(finding);
            }
        }
        return findings;
    }

    /// This checker supports PureFTPd
    fn get_technology(&self) -> Technology {
        Technology::PureFTPd
    }
}