//! The TinyMCE checker.
//! This module contains the checker used to determine if TinyMCE is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct TinyMCEChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> TinyMCEChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: return s={$:b,majorVersion:"4",minorVersion:"6.2",
        let body_regex = Regex::new(
            r#"(?P<wholematch>[^a-z]majorVersion\s*:\s*['"](?P<version1>\d+)['"]\s*,\s*minorVersion\s*:\s*['"](?P<version2>\d+\.\d+)['"])"#
        )
            .unwrap();

        // Example: return s={$:b,minorVersion:"6.2",majorVersion:"4"
        let body_regex_alternative = Regex::new(
            r#"(?P<wholematch>[^a-z]minorVersion\s*:\s*['"](?P<version2>\d+\.\d+)['"]\s*,\s*majorVersion\s*:\s*['"](?P<version1>\d+)['"])"#
        )
        .unwrap();

        regexes.insert("http-body", body_regex);
        regexes.insert("http-body-alternative", body_regex_alternative);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running TinyMCEChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body")
            .expect("Regex \"http-body\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex TinyMCE/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "TinyMCE", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        let caps_result = self
            .regexes
            .get("http-body-alternative")
            .expect("Regex \"http-body-alternative\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex TinyMCE/http-body-alternative matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "TinyMCE", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        None
    }
}

impl<'a> HttpChecker for TinyMCEChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running TinyMCEChecker::check_http()");
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
        Technology::TinyMCE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = TinyMCEChecker::new();
        let body1 = r#"return s={$:b,majorVersion:"4",minorVersion:"6.1","#;
        let url1 = "https://www.example.com/js/file.js";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "majorVersion:\"4\",minorVersion:\"6.1\"",
            "TinyMCE",
            Some("4.6.1"),
            Some(url1),
        );

        let body2 = r#"b , majorVersion : '2' , minorVersion : '1.4'"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "majorVersion : '2' , minorVersion : '1.4'",
            "TinyMCE",
            Some("2.1.4"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = TinyMCEChecker::new();
        let body = r#"var f = "TinyMCE"; majorVersion="3.11.9";"#;
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
        let checker = TinyMCEChecker::new();
        let body1 = r#"return s={$:b,minorVersion:"6.2", majorVersion:"4""#;
        let url1 = "https://www.example.com/g.js";
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
            "minorVersion:\"6.2\", majorVersion:\"4\"",
            "TinyMCE",
            Some("4.6.2"),
            Some(url1),
        );

        let body2 = r#"d,minorVersion: '6.2', majorVersion: '8'"#;
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
            "minorVersion: '6.2', majorVersion: '8'",
            "TinyMCE",
            Some("8.6.2"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = TinyMCEChecker::new();
        let body1 = r#"TinyMCE 39.0.1 is not installed here."#;
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
