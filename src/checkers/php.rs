//! The PHP checker.
//! This module contains the checker used to determine if PHP is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
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
        let header_regex =
            Regex::new(r"(?P<wholematch>.*PHP\/(?P<version>\d+\.\d+(\.\d+(\.\d+)?)?).*)").unwrap();
        regexes.insert("http-header", header_regex);
        Self { regexes: regexes }
    }

    /// Check in the HTTP headers.
    fn check_http_headers(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running PHPChecker::check_http_headers() on {}",
            url_response.url
        );
        // Check the HTTP headers of each UrlResponse
        let headers_to_check =
            url_response.get_headers(&vec!["Server".to_string(), "X-powered-by".to_string()]);

        // Check in the headers to check that were present in this UrlResponse
        for (header_name, header_value) in headers_to_check {
            trace!("Checking header: {} / {}", header_name, header_value);
            let caps_result = self
                .regexes
                .get("http-header")
                .expect("Regex \"http-header\" not found.")
                .captures(&header_value);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex PHP/http-header matches");
                let caps = caps_result.unwrap();
                return Some(
                    self.extract_finding_from_captures(
                        caps,
                        url_response,
                        40,
                        40,
                        "PHP",
                        &format!("$techno_name$$techno_version$ has been identified using the HTTP header \"{}: $evidence$\" returned at the following URL: $url_of_finding$", header_name)
                    )
                );
            }
        }
        None
    }
}

impl<'a> HttpChecker for PHPChecker<'a> {
    /// Check if the asset is running PHP.
    /// It looks in the following HTTP headers:
    /// - Server
    /// - X-Powered-By
    /// and in the "not found" page content
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running PHPChecker::check_http()");
        for url_response in data {
            let response = self.check_http_headers(url_response);
            if response.is_some() {
                return response;
            }
        }
        return None;
    }

    /// The technology supported by the checker.
    fn get_technology(&self) -> Technology {
        Technology::PHP
    }
}
