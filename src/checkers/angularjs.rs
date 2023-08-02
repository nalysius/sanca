//! The AngularJS (1.x) checker.
//! This module contains the checker used to determine if AngularJS is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct AngularJSChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> AngularJSChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /**
        //           * @license AngularJS v1.8.2
        //
        // or
        //
        // /*
        //  * AngularJS v1.8.2
        //
        // Note: (?m) enables multi line mode. So, ^ marks the beginning of the line, not
        // the beginning of the whole input
        let comment_regex = Regex::new(
            r"(?m)^\s+(\*\s+)?(?P<wholematch>(@license\s+)?AngularJS\s+v(?P<version>\d+\.\d+\.\d+))"
        )
        .unwrap();

        // Example: ] http://errors.angularjs.org/1.8.2/
        // 'https://errors.angularjs.org/1.8.2/'
        let body_minified_regex =
            Regex::new(r#"(\] |'|\\n)(?P<wholematch>https?:\/\/errors.angularjs.org\/(?P<version>\d+\.\d+\.\d+)\/)"#)
                .unwrap();

        regexes.insert("http-body-comment", comment_regex);
        regexes.insert("http-body-minified", body_minified_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running AngularJSChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex AngularJS/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "AngularJS", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        let caps_result = self
            .regexes
            .get("http-body-minified")
            .expect("Regex \"http-body-minified\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex AngularJS/http-body-minified matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 10, 30, "AngularJS", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }
        None
    }
}

impl<'a> HttpChecker for AngularJSChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
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
        Technology::AngularJS
    }
}
