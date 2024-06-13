//! The MySQL checker.
//! This module contains the checker used to determine if MySQL is
//! used by the asset.
//! https://www.mysql.com

use std::collections::HashMap;

use super::{Checker, TcpChecker};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The MySQL checker
pub struct MySQLChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> Checker for MySQLChecker<'a> {}

impl<'a> MySQLChecker<'a> {
    /// Creates a new MySQLChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: S
        // 5.7.37-nmm1-logm{pX^4gw9JD]Sg4mysql_native_password
        //
        // OR
        //
        // 8.0.36-0ubuntu0.20.04.1$en#@�bXL<%m6k/Dcaching_sha2_password
        //
        // (?s) means that . also matches a newline.
        let regex =
            Regex::new(r"(?s)(?P<wholematch>(?P<version1>\d+\.\d+(\.\d+)?).+_password)").unwrap();
        // MySQL banner contains characters which are replaced by the
        // replacement character (U+FFFD). Splitting an evidence on this
        // character makes the program panic because it's a multi-bytes
        // character. Instead, take the whole banner.
        regexes.insert("mysql-banner", (regex, 100, 100));
        Self { regexes: regexes }
    }
}

impl<'a> TcpChecker for MySQLChecker<'a> {
    /// Check if the asset is running MySQL.
    /// It looks for the MySQL banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        trace!("Running MySQLChecker::check_tcp()");
        // For each item, check if it's an MySQL banner
        for item in data {
            trace!("Checking item: {}", item);
            // Avoid false positive when MariaDB is present in the banner
            if item.clone().to_lowercase().contains("mariadb") {
                trace!("Item contains \"mariadb\", ignored");
                continue;
            }

            let banner_regex_params = self
                .regexes
                .get("mysql-banner")
                .expect("Regex MySQL/mysql-banner not found");
            let (regex, keep_left, keep_right) = banner_regex_params;
            let caps_result = regex.captures(&item);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex MySQL/mysql-banner matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    Technology::MySQL,
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" in its banner",
		));
            }
        }
        return None;
    }

    /// This checker supports MySQL
    fn get_technology(&self) -> Technology {
        Technology::MySQL
    }
}
