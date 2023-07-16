//! The MariaDB checker.
//! This module contains the checker used to determine if MariaDB is
//! used by the asset.

use crate::models::{Finding, Technology};
use super::TcpChecker;
use regex::Regex;

/// The MariaDB checker
pub struct MariaDBChecker {
    /// The regex used to recognize MariaDB
    regex: Regex
}

impl MariaDBChecker {
    /// Creates a new MariaDBChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: q
        // 5.5.5-10.10.2-MariaDB-1:10.10.2+maria~ubu1804CZA"$-TB,R-=xdmx1+%s:bamysql_native_password
        let regex = Regex::new(r"\d+\.\d+\.\d+\-(?P<mariadbversion>\d+\.\d+\.\d+)-MariaDB").unwrap();
        Self {
            regex: regex
        }
    }
}


impl TcpChecker for MariaDBChecker {
    /// Check if the asset is running MariaDB.
    /// It looks for the MariaDB banner.
    fn check(&self, data: &[String]) -> Option<Finding> {
        // For each item, check if it's an MariaDB banner
        for item in data {

            let caps_result = self.regex.captures(item);
            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                let version: String = caps["mariadbversion"].to_string();
                let evidence_text = format!(
                    "MariaDB {} has been identified using the banner it presents after initiating a TCP connection: {}",
                    version,
                    item
                );

                return Some(Finding::new("MariaDB", Some(&version), item, &evidence_text, None));
            }
        }
        return None;
    }

    /// This checker supports MariaDB
    fn get_technology(&self) -> Technology {
        Technology::MariaDB
    }
}