//! The Exim checker.
//! This module contains the checker used to determine if Exim is
//! used by the asset.

use std::collections::HashMap;

use super::TcpChecker;
use crate::models::{Finding, Technology};
use log::{info, trace};
use regex::Regex;

/// The Exim checker
pub struct EximChecker<'a> {
    /// The regexes used to recognize Exim
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> EximChecker<'a> {
    /// Creates a new EximChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: 220 test.example.com ESMTP Exim 4.96 Mon, 10 Jul 2023 19:39:15 +0300
        // Date / time are ignored
        let regex = Regex::new(r"^\d\d\d ([a-zA-Z0-9-]+\.)?([a-zA-Z0-9-]+\.)?[a-zA-Z0-9-]+ (?P<smtpprotocol>E?SMTP) Exim (?P<eximversion>\d+\.\d+) ").unwrap();
        regexes.insert("exim-banner", regex);
        Self { regexes: regexes }
    }
}

impl<'a> TcpChecker for EximChecker<'a> {
    /// Check if the asset is running Exim.
    /// It looks for the Exim banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        trace!("Running EximChecker::check_tcp()");
        // For each item, check if it's an Exim banner
        for item in data {
            trace!("Checking item: {}", item);
            let caps_result = self
                .regexes
                .get("exim-banner")
                .expect("Regex \"exim-banner\" not found.")
                .captures(item);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex Exim/exim-banner matches");
                let caps = caps_result.unwrap();
                let exim_smtp_protocol: String = caps["smtpprotocol"].to_string();
                let exim_version: String = caps["eximversion"].to_string();
                let exim_evidence_text = format!(
                    "Exim {} has been identified running the {} protocol using the banner it presents after initiating a TCP connection: {}",
                    exim_version,
                    exim_smtp_protocol,
                    item
                );

                return Some(Finding::new(
                    "Exim",
                    Some(&exim_version),
                    item,
                    &exim_evidence_text,
                    None,
                ));
            }
        }
        return None;
    }

    /// This checker supports Exim
    fn get_technology(&self) -> Technology {
        Technology::Exim
    }
}
