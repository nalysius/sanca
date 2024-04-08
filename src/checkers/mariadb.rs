//! The MariaDB checker.
//! This module contains the checker used to determine if MariaDB is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, TcpChecker};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The MariaDB checker
pub struct MariaDBChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> Checker for MariaDBChecker<'a> {}

impl<'a> MariaDBChecker<'a> {
    /// Creates a new MariaDBChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: q
        // 5.5.5-10.10.2-MariaDB-1:10.10.2+maria~ubu1804CZA"$-TB,R-=xdmx1+%s:bamysql_native_password
        //
        // (?s) means that . also matches a newline.
        let regex =
            Regex::new(r"(?s)(?P<wholematch>\d+\.\d+\.\d+\-(?P<version1>\d+\.\d+\.\d+)-MariaDB.+)")
                .unwrap();
        // MariaDB banner contains characters which are replaced by the
        // replacement character (U+FFFD). Splitting an evidence on this
        // character makes the program panic because it's a multi-bytes
        // character. Instead, take the whole banner.
        regexes.insert("mariadb-banner", (regex, 100, 100));
        Self { regexes: regexes }
    }
}

impl<'a> TcpChecker for MariaDBChecker<'a> {
    /// Check if the asset is running MariaDB.
    /// It looks for the MariaDB banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        trace!("Running MariaDBChecker::check_tcp()");
        // For each item, check if it's an MariaDB banner
        for item in data {
            trace!("Checking item: {}", item);
            let banner_regex_params = self
                .regexes
                .get("mariadb-banner")
                .expect("Regex MariaDB/mariadb-banner not found");
            let (regex, keep_left, keep_right) = banner_regex_params;
            let caps_result = regex.captures(&item);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex MariaDB/mariadb-banner matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    "MariaDB",
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" in its banner",
		));
            }
        }
        return None;
    }

    /// This checker supports MariaDB
    fn get_technology(&self) -> Technology {
        Technology::MariaDB
    }
}
