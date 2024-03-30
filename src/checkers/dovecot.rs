//! The Dovecot checker.
//! This module contains the checker used to determine if Dovecot is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, TcpChecker};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
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
        let regex = Regex::new(r"(?P<wholematch>OK \[.+\] Dovecot .* ready\.)").unwrap();
        regexes.insert("dovecot-banner", regex);
        Self { regexes: regexes }
    }
}

impl<'a> Checker for DovecotChecker<'a> {}

impl<'a> TcpChecker for DovecotChecker<'a> {
    /// Check if the asset is running Dovecot.
    /// It looks for the Dovecot banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        trace!("Running DovecotChecker::check_tcp()");
        // For each item, check if it's a Dovecot banner
        for item in data {
            trace!("Checking item: {}", item);
            // The regex matches
            let caps_result = self
                .regexes
                .get("dovecot-banner")
                .expect("Regex \"dovecot-banner\" not found.")
                .captures(item);
            if caps_result.is_some() {
                info!("Regex Dovecot/dovecot-banner matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    20,
		    20,
		    "Dovecot",
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" in its banner",
		));
            }
        }
        return None;
    }

    /// This checker supports Dovecot
    fn get_technology(&self) -> Technology {
        Technology::Dovecot
    }
}
