//! The jQuery checker.
//! This module contains the checker used to determine if jQuery is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use regex::Regex;

/// The checker
pub struct JQueryChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> JQueryChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /*!
        //           *jQuery JavaScript Library v3.7.0
        //
        // or
        //
        // /*! jQuery v3.7.0 |
        let comment_regex = Regex::new(r"\/\*![\s\*]+(?P<wholematch>jQuery (JavaScript Library )?(v(?P<version>\d\.\d\.\d)))( |)?").unwrap();
        regexes.insert("http-body-comment", comment_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "jQuery"));
        }
        None
    }
}

impl<'a> HttpChecker for JQueryChecker<'a> {
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
        Technology::JQuery
    }
}
