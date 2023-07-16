//! The Dovecot checker.
//! This module contains the checker used to determine if Dovecot is
//! used by the asset.

use crate::models::{Finding, Technology};
use super::TcpChecker;
use regex::Regex;

/// The Dovecot checker
pub struct DovecotChecker {
    /// The regex used to recognize the software
    regex: Regex
}

impl DovecotChecker {
    /// Creates a new instance.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: * OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.
        // Example: +OK Dovecot (Ubuntu) ready.
        let regex = Regex::new(r"OK \[.+\] Dovecot .* ready\.").unwrap();
        Self {
            regex: regex
        }
    }
}


impl TcpChecker for DovecotChecker {
    /// Check if the asset is running Dovecot.
    /// It looks for the Dovecot banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        // For each item, check if it's a Dovecot banner
        for item in data {
            // The regex matches
            if self.regex.is_match(item) {
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