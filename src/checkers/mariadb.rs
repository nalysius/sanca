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
    /// The regexes used to recognize MariaDB
    regexes: HashMap<&'a str, Regex>,
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
        let regex =
            Regex::new(r"(?P<wholematch>\d+\.\d+\.\d+\-(?P<version1>\d+\.\d+\.\d+)-MariaDB)")
                .unwrap();
        regexes.insert("mariadb-banner", regex);
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
            let caps_result = self
                .regexes
                .get("mariadb-banner")
                .expect("Regex \"mariadb-banner\" not found.")
                .captures(item);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex MariaDB/mariadb-banner matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    30,
		    30,
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
