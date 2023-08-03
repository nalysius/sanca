//! The Tomcat checker.
//! This module contains the checker used to determine if Tomcat is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlRequestType, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The Tomcat checker
pub struct TomcatChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> TomcatChecker<'a> {
    /// Creates a new checker
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: <h3>Apache Tomcat/9.1.17</h3>
        let body_regex =
            Regex::new(r"<h3>(?P<wholematch>Apache Tomcat\/(?P<version>\d+\.\d+\.\d+))<\/h3>")
                .unwrap();

        regexes.insert("http-body", body_regex);
        Self { regexes: regexes }
    }

    /// Check for the technology in the body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running TomcatChecker::check_http_body() on {}",
            url_response.url
        );

        // Checks only on the not found page to avoid false positive
        if url_response.url.contains("/pageNotFoundNotFound") {
            let caps_result = self
                .regexes
                .get("http-body")
                .expect("Regex \"http-body\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Tomcat/http-body matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(caps, url_response, 45, 45, "Tomcat", "$techno_name$$techno_version$ has been identified by looking at its signature \"$evidence$\" at this page: $url_of_finding$"));
            }
        }
        None
    }
}

impl<'a> HttpChecker for TomcatChecker<'a> {
    /// Perform a HTTP scan.
    /// It looks in the following HTTP headers:
    /// - Server
    /// - X-Powered-By
    /// and in the "not found" page content
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running TomcatChecker::check_http()");
        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }

            trace!("Checking {}", url_response.url);
            // Check in response body
            let body_finding = self.check_http_body(url_response);
            if body_finding.is_some() {
                return body_finding;
            }
        }
        None
    }

    /// Get the technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::Tomcat
    }
}
