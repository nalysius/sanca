//! The Plesk checker.
//! This module contains the checker used to determine if Plesk is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlRequestType, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct PleskChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> PleskChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: <title>Plesk Obsidian 17.1.36</title>
        let login_regex = Regex::new(
            r"<title>(?P<wholematch>Plesk\s+[a-zA-Z0-9]+\s+(?P<version>\d+\.\d+\.\d+))</title>",
        )
        .unwrap();
        regexes.insert("http-body-login", login_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running PleskChecker::check_http_body() on {}",
            url_response.url
        );

        // Restrict the verification on the login page
        if url_response.url.contains("/login_up.php") {
            let caps_result = self
                .regexes
                .get("http-body-login")
                .expect("Regex \"http-body-login\" not found.")
                .captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex Plesk/http-body-documentation matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "Plesk", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
            }
        }

        None
    }
}

impl<'a> HttpChecker for PleskChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running PleskChecker::check_http()");
        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }

            let response = self.check_http_body(&url_response);
            if response.is_some() {
                return response;
            }
        }
        return None;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::Plesk
    }
}
