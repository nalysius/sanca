//! The MySQL checker.
//! This module contains the checker used to determine if MySQL is
//! used by the asset.

use crate::models::{Finding, Technology};
use super::TcpChecker;
use regex::Regex;

/// The MySQL checker
pub struct MySQLChecker {
    /// The regex used to recognize MySQL
    regex: Regex
}

impl MySQLChecker {
    /// Creates a new MySQLChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        // Example: S
        // 5.7.37-nmm1-logm{pX^4gw9JD]Sg4mysql_native_password
        let regex = Regex::new(r"(?P<mysqlversion>\d+\.\d+\.\d+?).+mysql_native_password").unwrap();
        Self {
            regex: regex
        }
    }
}


impl TcpChecker for MySQLChecker {
    /// Check if the asset is running MySQL.
    /// It looks for the MySQL banner.
    fn check(&self, data: &[String]) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        // For each item, check if it's an MySQL banner
        for item in data {
            // Avoid false positive when MariaDB is present in the banner
            if item.clone().to_lowercase().contains("mariadb") {
                continue;
            }

            let caps_result = self.regex.captures(item);
            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                let version: String = caps["mysqlversion"].to_string();
                let evidence_text = format!(
                    "MySQL {} has been identified using the banner it presents after initiating a TCP connection: {}",
                    version,
                    item
                );

                let finding = Finding::new("MySQL", Some(&version), item, &evidence_text, None);
                findings.push(finding);
            }
        }
        return findings;
    }

    /// This checker supports MySQL
    fn get_technology(&self) -> Technology {
        Technology::MySQL
    }
}