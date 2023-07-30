//! The Pure-FTPd checker.
//! This module contains the checker used to determine if Pure-FTPd is
//! used by the asset.

use std::collections::HashMap;

use super::TcpChecker;
use crate::models::{Finding, Technology};
use log::{info, trace};
use regex::Regex;

/// The Pure-FTPd checker
pub struct PureFTPdChecker<'a> {
    /// The regexes used to recognize Pure-FTPd
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> PureFTPdChecker<'a> {
    /// Creates a new PureFTPdChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: 220---------- Welcome to Pure-FTPd [name] [TLS] ----------
        let regex = Regex::new(r"Welcome to Pure-FTPd \[(?P<srvname>[a-zA-z0-9-_.]+)\]").unwrap();
        regexes.insert("pureftpd-banner", regex);
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
            let caps_result = self
                .regexes
                .get("pureftpd-banner")
                .expect("Regex \"pureftpd-banner\" not found.")
                .captures(item);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex PureFTPd/pureftpd-banner matches");
                let caps = caps_result.unwrap();
                let srvname: String = caps["srvname"].to_string();
                // The banner can be several line long, so truncate it and take only the first one
                let mut evidence = item[0..item.find("\r\n").unwrap_or(item.len() - 1)].to_string();
                // If the banner has been trucated, say it
                if evidence.len() < item.len() {
                    trace!("Truncate evidence");
                    evidence.push_str("[...]");
                }
                let evidence_text = format!(
                    "Pure-FTPd has been found under the name \"{}\" using the banner it presents after initiating a TCP connection: {}",
                    srvname,
                    evidence
                );

                return Some(Finding::new(
                    "Pure-FTPd",
                    None,
                    &evidence,
                    &evidence_text,
                    None,
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
