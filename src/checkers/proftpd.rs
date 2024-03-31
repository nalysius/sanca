//! The ProFTPD checker.
//! This module contains the checker used to determine if ProFTPd is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, TcpChecker};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The ProFTPD checker
pub struct ProFTPDChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> Checker for ProFTPDChecker<'a> {}

impl<'a> ProFTPDChecker<'a> {
    /// Creates a new ProFTPDChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: 220 ProFTPD 1.3.5b Server (ProFTPD) [11.22.33.44]
        // The IP address is ignored by the regex
        let regex = Regex::new(r"^(?P<wholematch>\d\d\d ProFTPD (?P<version1>\d+\.\d+\.\d+[a-z]?) Server \((?P<proftpdname>.+)\))").unwrap();
        regexes.insert("proftpd-banner", (regex, 30, 30));
        Self { regexes: regexes }
    }
}

impl<'a> TcpChecker for ProFTPDChecker<'a> {
    /// Check if the asset is running ProFTPD.
    /// It looks for the ProFTPD banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        trace!("Running ProFTPDChecker::check_tcp()");
        // For each item, check if it's an ProFTPD banner
        for item in data {
            trace!("Checking item: {}", item);

            let banner_regex_params = self
                .regexes
                .get("proftpd-banner")
                .expect("Regex ProFTPD/proftpd-banner not found");
            let (regex, keep_left, keep_right) = banner_regex_params;
            let caps_result = regex.captures(&item);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex ProFTPD/proftpd-banner matches");
                let caps = caps_result.unwrap();
                let _proftpd_name = caps.name("proftpdname");
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    "ProFTPD",
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" in its banner",
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
