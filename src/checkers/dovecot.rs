//! The Dovecot checker.
//! This module contains the checker used to determine if Dovecot is
//! used by the asset.
//! https://dovecot.org

use std::collections::HashMap;

use super::{Checker, TcpChecker};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The Dovecot checker
pub struct DovecotChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
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
        regexes.insert("dovecot-banner", (regex, 20, 20));
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
            let banner_regex_params = self
                .regexes
                .get("dovecot-banner")
                .expect("Regex Dovecot/dovecot-banner not found");
            let (regex, keep_left, keep_right) = banner_regex_params;
            let caps_result = regex.captures(&item);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Dovecot/dovecot-banner matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    Technology::Dovecot,
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
