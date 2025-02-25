//! The Highcharts checker.
//! This module contains the checker used to determine if Highcharts is
//! used by the asset.
//! https://www.highcharts.com

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct HighchartsChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> HighchartsChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: Highcharts JS v11.1.0 (2023-06-05)
        // TODO: add unit tests for this
        let body_comment_regex = Regex::new(r#"\s*(?P<wholematch>Highcharts JS v(?P<version1>\d+\.\d+\.\d+)\s*\(\d\d\d\d-\d\d-\d\d\))"#)
        .unwrap();

        // Example: {product:"Highstock",version:"6.0.3",
        let body_regex = Regex::new(
            r#"(?P<wholematch>Highcharts.+\{\s*product\s*:\s*"High[a-zA-Z0-9]+"\s*,\s*version\s*:\s*"(?P<version1>\d+\.\d+\.\d+)")"#,
        )
        .unwrap();

        let body_regex_alternative = Regex::new(
            r#"(?P<wholematch>Highcharts.+version\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"])"#,
        )
        .unwrap();

        regexes.insert("http-body", (body_regex, 20, 20));
        regexes.insert("http-body-alternative", (body_regex_alternative, 10, 20));
        regexes.insert("http-body-comment", (body_comment_regex, 10, 20));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running HighchartsChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex Highcharts/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    Technology::Highcharts,
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for HighchartsChecker<'a> {}

impl<'a> HttpChecker for HighchartsChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running HighchartsChecker::check_http()");
        let mut findings = Vec::new();
        for url_response in data {
            let response = self.check_http_body(&url_response);
            if response.is_some() {
                findings.push(response.unwrap());
            }
        }
        return findings;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::Highcharts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = HighchartsChecker::new();
        let body1 = r#"var a = 42;Highcharts.b = 1;var j = {product: "Highstock", version: "6.0.1"};var b = 1;"#;
        let url1 = "https://www.example.com/js/file.js";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "version: \"6.0.1\"",
            Technology::Highcharts,
            Some("6.0.1"),
            Some(url1),
        );

        let body2 = r#"var a = 42;Highcharts.b = 1;var j={ product:"Highstock",version:"6.0.1"};var b = 1;"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "version:\"6.0.1\"",
            Technology::Highcharts,
            Some("6.0.1"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = HighchartsChecker::new();
        let body = r#"var f = "Highcharts"; VERSION="6.0.2";"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
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
        let checker = HighchartsChecker::new();
        let body1 =
            r#"var a = 42;Highcharts.b = 1;var j={product:"Highstock",version:"6.0.1"};var b = 1;"#;
        let url1 = "https://www.example.com/h.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
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
            "version:\"6.0.1\"",
            Technology::Highcharts,
            Some("6.0.1"),
            Some(url1),
        );

        let body2 =
            r#"var a = 42;Highcharts.b = 1;var j={product:"Highstock",version:"6.0.1"};var b = 1;"#;
        let url2 = "https://www.example.com/g.js";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::JavaScript, 200);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_valid, url_response_invalid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "version:\"6.0.1\"",
            Technology::Highcharts,
            Some("6.0.1"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = HighchartsChecker::new();
        let body1 = r#"Highcharts v6.0.1 is not installed here."#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"It should not be detected"#;
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/abc-1/de-f1",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());
    }
}
