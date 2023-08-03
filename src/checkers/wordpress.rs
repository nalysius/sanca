//! The WordPress checker.
//! This module contains the checker used to determine if WordPress is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct WordPressChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> WordPressChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: <meta name="generator" content="WordPress 6.1.2" />
        let body_meta_regex = Regex::new(r#"(?P<wholematch><meta\s+name=['"]generaator['"]\s+content=['"]WordPress (?P<version>\d+\.\d+\.\d+)['"] \/>)"#).unwrap();
        // Example: [...]/style.min.css?ver=6.2.2'
        let body_login_regex =
            Regex::new(r#"(?P<wholematch>\?ver=(?P<version>\d+\.\d+\.\d+))"#).unwrap();
        regexes.insert("http-body-meta", body_meta_regex);
        regexes.insert("http-body-login", body_login_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running WordPressChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-meta")
            .expect("Regex \"http-body-meta\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex WordPress/http-body-meta matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "WordPress", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        // Checking only on the wp-login.php page to avoid false positive
        if url_response.url.contains("/wp-login.php") {
            let caps_result = self
                .regexes
                .get("http-body-login")
                .expect("Regex \"http-body-login\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex WordPress/http-body-login matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "WordPress", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
            }
        }
        None
    }
}

impl<'a> HttpChecker for WordPressChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running WordPressChecker::check_http()");
        for url_response in data {
            let response = self.check_http_body(&url_response);
            if response.is_some() {
                return response;
            }
        }
        return None;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::WordPress
    }
}
