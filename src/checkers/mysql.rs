//! The MySQL checker.
//! This module contains the checker used to determine if MySQL is
//! used by the asset.

use std::collections::HashMap;

use super::TcpChecker;
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The MySQL checker
pub struct MySQLChecker<'a> {
    /// The regexes used to recognize MySQL
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> MySQLChecker<'a> {
    /// Creates a new MySQLChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: S
        // 5.7.37-nmm1-logm{pX^4gw9JD]Sg4mysql_native_password
        let regex = Regex::new(r"(?P<mysqlversion>\d+\.\d+\.\d+?).+mysql_native_password").unwrap();
        regexes.insert("mysql-banner", regex);
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

            let caps_result = self
                .regexes
                .get("mysql-banner")
                .expect("Regex \"mysql-banner\" not found")
                .captures(item);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex MySQL/mysql-banner matches");
                let caps = caps_result.unwrap();
                let version: String = caps["mysqlversion"].to_string();
                let evidence_text = format!(
                    "MySQL {} has been identified using the banner it presents after initiating a TCP connection: {}",
                    version,
                    item
                );

                return Some(Finding::new(
                    "MySQL",
                    Some(&version),
                    item,
                    &evidence_text,
                    None,
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
