//! The CKEditor checker.
//! This module contains the checker used to determine if CKEditor is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
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
        // Example: const x="39.0.1"[...]CKEDITOR_VERSION=x
        let body_regex = Regex::new(
            r#"(?P<wholematch>const [a-zA-Z0-9_]+\s*=\s*['"](?P<version>\d+\.\d+\.\d+)['"].+CKEDITOR_VERSION\s*=\s*[a-zA-z0-9_]+)"#,
        )
        .unwrap();

        regexes.insert("http-body", body_regex);
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
            return Some(self.extract_finding_from_captures(caps, url_response, 20, 20, "CKEditor", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        None
    }
}

impl<'a> HttpChecker for CKEditorChecker<'a> {
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
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript);
        let finding = checker.check_http_body(&url_response_valid);
        check_finding_fields(
            finding,
            "const x=\"39.0.1\"",
            "CKEditor",
            Some("39.0.1"),
            Some(url1),
        );

        let body2 = r#"var a = 10; const _ = '39.0.1'; var b1 = 20;CKEDITOR_VERSION=_;a.that();"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        check_finding_fields(
            finding,
            "const _ = '39.0.1'",
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
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = CKEditorChecker::new();
        let body1 = r#"var a = 10; const _ ='39.0.1'; var b1 = 20; CKEDITOR_VERSION = _; a.that();"#;
        let url1 = "https://www.example.com/g.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to find in body",
            UrlRequestType::Default,
        );
        let finding = checker.check_http(&[url_response_invalid, url_response_valid]);
        check_finding_fields(
            finding,
            "const _ ='39.0.1'",
            "CKEditor",
            Some("39.0.1"),
            Some(url1),
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
}
