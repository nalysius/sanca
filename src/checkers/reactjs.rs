//! The ReactJS checker.
//! This module contains the checker used to determine if ReactJS is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct ReactJSChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> ReactJSChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: var ReactVersion = '18.2.0';
        let source_code_regex = Regex::new(
            r#"\s*(?P<wholematch>var\s+ReactVersion\s*=\s*['"](?P<version>\d+\.\d+(\.\d+)?)['"])"#,
        )
        .unwrap();

        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running ReactJSChecker::check_http_body() on {}",
            url_response.url
        );

        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex ReactJS/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                10,
                20,
                "ReactJS",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }
        None
    }
}

impl<'a> HttpChecker for ReactJSChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running ReactJSChecker::check_http()");
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
        Technology::ReactJS
    }
}
