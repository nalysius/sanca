//! The PHP checker.
//! This module contains the checker used to determine if PHP is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use regex::Regex;

/// The PHP checker
pub struct PHPChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> PHPChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: PHP/7.1.33.12
        let header_regex = Regex::new(r"PHP\/(?P<version>\d+\.\d+(\.\d+(\.\d+)?)?)").unwrap();
        regexes.insert("http-header", header_regex);
        Self { regexes: regexes }
    }
}

impl<'a> HttpChecker for PHPChecker<'a> {
    /// Check if the asset is running PHP.
    /// It looks in the following HTTP headers:
    /// - Server
    /// - X-Powered-By
    /// and in the "not found" page content
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        for url_response in data {
            // Check the HTTP headers of each UrlResponse
            let headers_to_check =
                url_response.get_headers(&vec!["Server".to_string(), "X-powered-by".to_string()]);

            // Check in the headers to check that were present in this UrlResponse
            for (header_name, header_value) in headers_to_check {
                let caps_result = self
                    .regexes
                    .get("http-header")
                    .expect("Regex \"http-header\" not found.")
                    .captures(&header_value);

                // The regex matches
                if caps_result.is_some() {
                    let caps = caps_result.unwrap();
                    let evidence = &format!("{}: {}", header_name, header_value);
                    let version = caps["version"].to_string();
                    // Add a space in the version, so in the evidence text we
                    // avoid a double space if the version is not found
                    let version_text = format!(" {}", version);

                    let evidence_text = format!(
                        "PHP{} has been identified using the HTTP header \"{}\" returned at the following URL: {}",
                        version_text,
                        evidence,
                        url_response.url
                    );

                    return Some(Finding::new(
                        "PHP",
                        Some(&version),
                        &evidence,
                        &evidence_text,
                        Some(&url_response.url),
                    ));
                }
            }
        }
        return None;
    }

    /// This checker supports Apache httpd
    fn get_technology(&self) -> Technology {
        Technology::Httpd
    }
}
