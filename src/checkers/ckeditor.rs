//! The CKEditor checker.
//! This module contains the checker used to determine if CKEditor is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct CKEditorChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> CKEditorChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: x.CKEDITOR_VERSION="39.0.1"
        let body_regex = Regex::new(
            r#"(?P<wholematch>[a-zA-Z0-9_]+\.CKEDITOR_VERSION\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"])"#,
        )
        .unwrap();

        // Example: const x="39.0.1"[...]CKEDITOR_VERSION=x
        let body_alternative_regex = Regex::new(
            r#"(?P<wholematch>const [a-zA-Z0-9_]+\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"].+CKEDITOR_VERSION\s*=\s*[a-zA-z0-9_]+)"#,
        )
        .unwrap();

        regexes.insert("http-body", body_regex);
        regexes.insert("http-body-alternative", body_alternative_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running CKEditorChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body")
            .expect("Regex \"http-body\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex CKEditor/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, Some(url_response), 20, 20, "CKEditor", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        let caps_result = self
            .regexes
            .get("http-body-alternative")
            .expect("Regex \"http-body-alternative\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex CKEditor/http-body-alternative matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, Some(url_response), 20, 20, "CKEditor", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        None
    }
}

impl<'a> Checker for CKEditorChecker<'a> {}

impl<'a> HttpChecker for CKEditorChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running CKEditorChecker::check_http()");
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
        Technology::CKEditor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = CKEditorChecker::new();
        let body1 = r#"var a = 10; const x="39.0.1"; doThat(); CKEDITOR_VERSION=x;a.that();"#;
        let url1 = "https://www.example.com/js/file.js";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "const x=\"39.0.1\"",
            "CKEditor",
            Some("39.0.1"),
            Some(url1),
        );

        let body2 = r#"const a = 10; x.CKEDITOR_VERSION="39.0.1"; a.b();"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "x.CKEDITOR_VERSION=\"39.0.1\"",
            "CKEditor",
            Some("39.0.1"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = CKEditorChecker::new();
        let body = r#"var f = "CKEditor"; VERSION="39.0.1";"#;
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
        let checker = CKEditorChecker::new();
        let body1 =
            r#"var a = 10; const _ ='39.0.1'; var b1 = 20; CKEDITOR_VERSION = _; a.that();"#;
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
            "const _ ='39.0.1'",
            "CKEditor",
            Some("39.0.1"),
            Some(url1),
        );

        let body2 = r#"x.CKEDITOR_VERSION="39.0.1"; this.that = "test";"#;
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
            "x.CKEDITOR_VERSION=\"39.0.1\"",
            "CKEditor",
            Some("39.0.1"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = CKEditorChecker::new();
        let body1 = r#"CKEditor 39.0.1 is not installed here."#;
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
