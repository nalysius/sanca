//! The Apache httpd checker.
//! This module contains the checker used to determine if Apache httpd is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use regex::{Match, Regex};

/// The Apache httpd checker
pub struct ApacheHttpdChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> ApacheHttpdChecker<'a> {
    /// Creates a new ApacheHttpdChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: Apache/2.4.52 (Debian)
        let header_regex = Regex::new(r"^Apache(\/(?P<httpdversion>\d+(\.\d+(\.\d+)?)?))?").unwrap();
        regexes.insert("http-header", header_regex);
        Self { regexes: regexes }
    }
}

impl<'a> HttpChecker for ApacheHttpdChecker<'a> {
    /// Check if the asset is running Apache httpd.
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
                    let httpd_version_match: Option<Match> = caps.name("httpdversion");
                    let mut httpd_version: Option<&str> = None;
                    let mut httpd_version_text = String::new();
                    if httpd_version_match.is_some() {
                        httpd_version = Some(httpd_version_match.unwrap().as_str());
                        // Add a space in the version, so in the evidence text we
                        // avoid a double space if the version is not found
                        httpd_version_text = format!(" {}", httpd_version.unwrap());
                    }

                    let evidence_text = format!(
                        "Apache httpd{} has been identified using the HTTP header \"{}\" returned at the following URL: {}",
                        httpd_version_text,
                        evidence,
                        url_response.url
                    );

                    return Some(Finding::new(
                        "Apache httpd",
                        httpd_version,
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
