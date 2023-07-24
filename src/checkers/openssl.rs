//! The OpenSSL checker.
//! This module contains the checker used to determine if OpenSSL is
//! used by the asset and in which version.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use regex::Regex;

/// The OpenSSL checker
pub struct OpenSSLChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> OpenSSLChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: OpenSSL/1.0.2k-fips
        let header_regex =
            Regex::new(r"(?P<wholematch>.*OpenSSL\/(?P<version>\d+\.\d+\.\d+([a-z])?(-[a-z]+)?).*)").unwrap();
        regexes.insert("http-header", header_regex);
        Self { regexes: regexes }
    }

    /// Checks in the HTTP headers.
    fn check_http_headers(&self, url_response: &UrlResponse) -> Option<Finding> {
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
                return Some(self.extract_finding_from_captures(caps, url_response, 40, 40, "OpenSSL", &format!("$techno_name$$techno_version$ has been identified using the HTTP header \"{}: $evidence$\" returned at the following URL: $url_of_finding$", header_name)));
            }
        }
        None
    }
}

impl<'a> HttpChecker for OpenSSLChecker<'a> {
    /// Check if the asset is running OpenSSL.
    /// It looks in the following HTTP headers:
    /// - Server
    /// - X-Powered-By
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        for url_response in data {
            let response = self.check_http_headers(url_response);
            if response.is_some() {
                return response;
            }
        }
        return None;
    }

    /// This checker supports Apache httpd
    fn get_technology(&self) -> Technology {
        Technology::OpenSSL
    }
}
