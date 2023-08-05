//! The Angular (2+) checker.
//! This module contains the checker used to determine if Angular is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct AngularChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> AngularChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: CORE="@angular/core"[...]var VERSION2 = new Version("15.2.4")
        let source_code_regex = Regex::new(
            r#"(?P<wholematch>CORE=['"]@angular\/.+['"].+new\s+Version\(['"](?P<version>\d+\.\d+\.\d+)['"]\))"#,
        )
        .unwrap();

        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running AngularChecker::check_http_body() on {}",
            url_response.url
        );

        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Angular/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                15,
                21,
                "Angular",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }
        None
    }
}

impl<'a> HttpChecker for AngularChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running AngularChecker::check_http()");
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
        Technology::Angular
    }
}
