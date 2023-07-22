//! The Dovecot checker.
//! This module contains the checker used to determine if Dovecot is
//! used by the asset.

use std::collections::HashMap;

use super::TcpChecker;
use crate::models::{Finding, Technology};
use regex::Regex;

/// The Dovecot checker
pub struct DovecotChecker<'a> {
    /// The regexes used to recognize the software
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> DovecotChecker<'a> {
    /// Creates a new instance.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.
        // Example: +OK Dovecot (Ubuntu) ready.
        let regex = Regex::new(r"OK \[.+\] Dovecot .* ready\.").unwrap();
        regexes.insert("dovecot-banner", regex);
        Self { regexes: regexes }
    }
}

impl<'a> TcpChecker for DovecotChecker<'a> {
    /// Check if the asset is running Dovecot.
    /// It looks for the Dovecot banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        // For each item, check if it's a Dovecot banner
        for item in data {
            // The regex matches
            if self
                .regexes
                .get("dovecot-banner")
                .expect("Regex \"dovecot-banner\" not found.")
                .is_match(item)
            {
                let evidence_text = format!(
                    "Dovecot has been identified using the banner it presents after initiating a TCP connection: {}",
                    item
                );

                return Some(Finding::new("Dovecot", None, item, &evidence_text, None));
            }
        }
        return None;
    }

    /// This checker supports Dovecot
    fn get_technology(&self) -> Technology {
        Technology::Dovecot
    }
}
