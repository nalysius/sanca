//! The Lodash checker.
//! This module contains the checker used to determine if Lodash is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use regex::{Regex, RegexBuilder};

/// The checker
pub struct LodashChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> LodashChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /**
        //            * @license
        //            * Lodash <https://lodash.com/>
        //          [...truncated...]
        // var VERSION = '4.17.15';
        //
        // or
        //
        // /**
        //   * @license
        //   * Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE
        //   */
        //  [...truncated...]
        // ,An.VERSION="4.17.15"
        //
        // TODO: make the match multi-lines, to use the license header. It would help
        // to avoid false positive.
        let body_regex = RegexBuilder::new(
            r#"lodash.+(?P<wholematch>(var )?VERSION ?= ?['"](?P<version>\d+\.\d+\.\d+)['"])[;,]?"#,
        )
        .multi_line(true)
        .build()
        .unwrap();

        let body_minified_regex = RegexBuilder::new(
            r#"(?P<wholematch>VERSION ?= ?[a-zA-Z0-9]+[,;].+[a-zA-Z0-9]+=['"](?P<version>\d+\.\d+\.\d+)['"]).+lodash_placeholder"#,
        )
        .multi_line(true)
        .build()
        .unwrap();

        regexes.insert("http-body", body_regex);
        regexes.insert("http-body-minified", body_minified_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        let caps_result = self
            .regexes
            .get("http-body")
            .expect("Regex \"http-body\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "Lodash"));
        }

        let caps_result = self
            .regexes
            .get("http-body-minified")
            .expect("Regex \"http-body-minified\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 10, 30, "Lodash"));
        }
        None
    }
}

impl<'a> HttpChecker for LodashChecker<'a> {
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
        Technology::Lodash
    }
}
