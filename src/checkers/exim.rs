//! The Exim checker.
//! This module contains the checker used to determine if Exim is
//! used by the asset.
//! https://www.exim.org

use std::collections::HashMap;

use super::{Checker, TcpChecker};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The Exim checker
pub struct EximChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> Checker for EximChecker<'a> {}

impl<'a> EximChecker<'a> {
    /// Creates a new EximChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: 220 test.example.com ESMTP Exim 4.96 Mon, 10 Jul 2023 19:39:15 +0300
        // Date / time are ignored
        let regex = Regex::new(r"^(?P<wholematch>\d\d\d ([a-zA-Z0-9-]+\.)?([a-zA-Z0-9-]+\.)?[a-zA-Z0-9-]+ (?P<smtpprotocol>E?SMTP) Exim (?P<version>\d+\.\d+)) ").unwrap();
        regexes.insert("exim-banner", (regex, 20, 20));
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
            let banner_regex_params = self
                .regexes
                .get("exim-banner")
                .expect("Regex Exim/exim-banner not found");
            let (regex, keep_left, keep_right) = banner_regex_params;
            let caps_result = regex.captures(&item);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Exim/exim-banner matches");
                let caps = caps_result.unwrap();
                let _exim_smtp_protocol = caps.name("smtpprotocol");
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    Technology::Exim,
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" in its banner",
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
