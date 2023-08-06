//! The Lodash checker.
//! This module contains the checker used to determine if Lodash is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

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
        //  [...]
        // lodash[...],An.VERSION="4.17.15"
        //
        let body_regex = Regex::new(
            r#"lodash.+(?P<wholematch>(var )?VERSION ?= ?['"](?P<version>\d+\.\d+\.\d+)['"])[;,]?"#,
        )
        .unwrap();

        let body_minified_regex = Regex::new(
            r#"(?P<wholematch>VERSION ?= ?[a-zA-Z0-9]+[,;].+[a-zA-Z0-9]+=['"](?P<version>\d+\.\d+\.\d+)['"]).+lodash_placeholder"#,
        )
        .unwrap();

        regexes.insert("http-body", body_regex);
        regexes.insert("http-body-minified", body_minified_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running LodashChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body")
            .expect("Regex \"http-body\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Lodash/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "Lodash", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        let caps_result = self
            .regexes
            .get("http-body-minified")
            .expect("Regex \"http-body-minified\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Lodash/http-body-minified matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 10, 30, "Lodash", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::UrlRequestType;
    #[test]
    fn source_code_matches() {
        let checker = LodashChecker::new();
        let body1 = r#"var a = 42;lodash.c();var VERSION= '4.17.15';var b = 1;"#;
        let mut url_response_valid = UrlResponse::new(
            "https://www.example.com/js/file.js",
            HashMap::new(),
            body1,
            UrlRequestType::JavaScript,
        );
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());

        let body2 = r#"a.b=10;VERSION = abc;a.c();var v="4.17.15"; a.lodash_placeholder"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
    }

    #[test]
    fn source_code_doesnt_matches() {
        let checker = LodashChecker::new();
        let body = r#"var f = "LodashPlaceholder"; VERSION="4.7.7";"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = LodashChecker::new();
        let body1 = r#"var a = 42;lodash.x = 0;var VERSION = "4.17.15";var b = 1;"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/g.js",
            HashMap::new(),
            body1,
            UrlRequestType::JavaScript,
        );
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert!(finding.is_some());

        let body2 = r#"a.e1(); VERSION=abc;a.c_1 = "10";var v="4.17.15"; a.lodash_placeholder;"#;
        let url_response_valid = UrlResponse::new(
            "https://www.example.com/g.js",
            HashMap::new(),
            body2,
            UrlRequestType::JavaScript,
        );
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_valid, url_response_invalid]);
        assert!(finding.is_some());
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = LodashChecker::new();
        let body1 = r#"Lodash v4.17.15 is not installed here."#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
        );
        let body2 = r#"It should not be detected"#;
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/abc-1/de-f1",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(finding.is_none());
    }

    #[test]
    fn finding_fields_are_valid() {
        let checker = LodashChecker::new();
        let body1 = r#"var a = "ok";lodash.x();var VERSION= "4.17.15";var b = "1""#;
        let url = "https://www.example.com/l.js";
        let url_response_valid1 =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::JavaScript);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());

        let finding = finding.unwrap();
        assert!(finding.url_of_finding.is_some());
        assert_eq!(url, finding.url_of_finding.unwrap());
        let expected_evidence = "4.17.15";
        assert!(finding.evidence.contains(expected_evidence));
        assert_eq!("Lodash", finding.technology);
        assert!(finding.version.is_some());
        assert_eq!("4.17.15", finding.version.unwrap());

        let evidence_text = finding.evidence_text;
        assert!(evidence_text.contains(url)); // URL of finding
        assert!(evidence_text.contains("Lodash 4.17.15")); // Technology / version
        assert!(evidence_text.contains(expected_evidence)); // Evidence
    }
}
