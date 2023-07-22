//! The ProFTPD checker.
//! This module contains the checker used to determine if ProFTPd is
//! used by the asset.

use std::collections::HashMap;

use super::TcpChecker;
use crate::models::{Finding, Technology};
use regex::Regex;

/// The ProFTPD checker
pub struct ProFTPDChecker<'a> {
    /// The regexes used to recognize ProFTPD
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> ProFTPDChecker<'a> {
    /// Creates a new ProFTPDChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: 220 ProFTPD 1.3.5b Server (ProFTPD) [11.22.33.44]
        // The IP address is ignored by the regex
        let regex = Regex::new(r"^\d\d\d ProFTPD (?P<proftpdversion>\d+\.\d+\.\d+[a-z]?) Server \((?P<proftpdname>.+)\)").unwrap();
        regexes.insert("proftpd-banner", regex);
        Self { regexes: regexes }
    }
}

impl<'a> TcpChecker for ProFTPDChecker<'a> {
    /// Check if the asset is running ProFTPD.
    /// It looks for the ProFTPD banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        // For each item, check if it's an ProFTPD banner
        for item in data {
            let caps_result = self
                .regexes
                .get("proftpd-banner")
                .expect("Regex \"proftpd-banner\" not found.")
                .captures(item);
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

                return Some(Finding::new(
                    "ProFTPD",
                    Some(&proftpd_version),
                    item,
                    &proftpd_evidence_text,
                    None,
                ));
            }
        }
        return None;
    }

    /// This checker supports ProFTPD
    fn get_technology(&self) -> Technology {
        Technology::ProFTPD
    }
}
