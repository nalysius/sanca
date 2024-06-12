//! The Jira checker.
//! This module contains the checker used to determine if Jira is
//! used by the asset.
//! https://www.atlassian.com/software/jira

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct JiraChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> JiraChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: <meta name="application-name" content="JIRA" data-name="jira" data-version="9.11.6">
        let source_code_regex =
            Regex::new(r#".*(?P<wholematch><meta\s+name\s*=\s*['"]application-name['"]\s+content\s*=\s*['"]JIRA['"]\s+data-name\s*=\s*['"]jira['"]\s+data-version\s*=\s*['"](?P<version1>\d+\.\d+\.\d+(\.\d+)?)['"])"#).unwrap();
        regexes.insert("http-body-source", (source_code_regex, 50, 50));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running JiraChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex Jira/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    "Jira",
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
            }
        }
        None
    }
}

impl<'a> Checker for JiraChecker<'a> {}

impl<'a> HttpChecker for JiraChecker<'a> {
    /// Check for a HTTP scan.
    ///
    /// Returns only one finding, otherwise findings would be duplicated each
    /// time it's found.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running JiraChecker::check_http()");

        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }

            let response = self.check_http_body(&url_response);
            if response.is_some() {
                return vec![response.unwrap()];
            }
        }
        return Vec::new();
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::Jira
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = JiraChecker::new();
        let body1 = r#" <meta name="application-name" content="JIRA" data-name="jira" data-version="9.11.6"> "#;
        let url1 = "https://www.example.com/jira/login";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "data-version=\"9.11.6\"",
            "Jira",
            Some("9.11.6"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = JiraChecker::new();
        let body = r#"Jira data version 9.11.6"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/jira/login",
            HashMap::new(),
            body,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = JiraChecker::new();
        let body1 = r#"   <meta name = "application-name" content= 'JIRA' data-name =  "jira" data-version  ="9.10.5"> <meta name="ajs-server-scheme" content="https"> "#;
        let url1 = "https://www.example.com/jira/";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "data-version  =\"9.10.5\"",
            "Jira",
            Some("9.10.5"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = JiraChecker::new();
        let body1 =
            r#"<meta name="jira-app" content="application" data-name="jira" data-version="9.1.1""#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/invalid/url",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );

        let body2 = "Jira version: 9.1.1";
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/jira",
            HashMap::new(),
            body2,
            UrlRequestType::JavaScript,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());
    }
}
