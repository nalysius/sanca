//! The Pure-FTPd checker.
//! This module contains the checker used to determine if Pure-FTPd is
//! used by the asset.
//! https://www.pureftpd.org/

use std::collections::HashMap;

use super::{Checker, TcpChecker};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The Pure-FTPd checker
pub struct PureFTPdChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> Checker for PureFTPdChecker<'a> {}

impl<'a> PureFTPdChecker<'a> {
    /// Creates a new PureFTPdChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: 220---------- Welcome to Pure-FTPd [name] [TLS] ----------
        let regex =
            Regex::new(r"(?P<wholematch>Welcome to Pure-FTPd \[(?P<srvname>[a-zA-z0-9-_.]+)\])")
                .unwrap();
        regexes.insert("pureftpd-banner", (regex, 30, 30));
        Self { regexes: regexes }
    }
}

impl<'a> TcpChecker for PureFTPdChecker<'a> {
    /// Check if the asset is running Pure-FTPd.
    /// It looks for the Pure-FTPd banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        trace!("Running PureFTPdChecker::check_tcp()");
        // For each item, check if it's an Pure-FTPd banner
        for item in data {
            trace!("Checker item: {}", item);
            let banner_regex_params = self
                .regexes
                .get("pureftpd-banner")
                .expect("Regex PureFTPd/pureftpd-banner not found");
            let (regex, keep_left, keep_right) = banner_regex_params;
            let caps_result = regex.captures(&item);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex PureFTPd/pureftpd-banner matches");
                let caps = caps_result.unwrap();
                let _srvname = caps.name("srvname");
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    Technology::PureFTPd,
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" in its banner",
		));
            }
        }
        return None;
    }

    /// This checker supports PureFTPd
    fn get_technology(&self) -> Technology {
        Technology::PureFTPd
    }
}
