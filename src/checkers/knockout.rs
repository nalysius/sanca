//! The Knockout checker.
//! This module contains the checker used to determine if Knockout is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct KnockoutChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> KnockoutChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: // Knockout JavaScript library v2.1.0
        // Example: * Knockout JavaScript library v3.5.0-rc
        let comment_regex = Regex::new(r"(\/\/|\*)\s*(?P<wholematch>Knockout (JavaScript [Ll]ibrary )?(v@?(?P<version1>\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?)))").unwrap();

        // Example: function(a,c,d){a[c]=d};a.version="2.1.0"
        let body_minified_regex = Regex::new(r#"(?P<wholematch>function\s*\(\s*[a-zA-Z0-9]+\s*,\s*[a-zA-Z0-9]+\s*,\s*[a-zA-Z0-9]+\s*\)\s*\{\s*[a-zA-Z0-9]+\[\s*[a-zA-Z0-9]+\s*\]\s*=\s*[a-zA-Z0-9]+\s*\}\s*[,;]\s*[a-zA-Z0-9]+\.version\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"]).+__RequestVerificationToken"#).unwrap();

        regexes.insert("http-body-comment", (comment_regex, 30, 30));
        regexes.insert("http-body-minified", (body_minified_regex, 30, 30));

        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running KnockoutChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex Knockout/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    "Knockout",
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for KnockoutChecker<'a> {}

impl<'a> HttpChecker for KnockoutChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running KnockoutChecker::check_http()");
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
        Technology::Knockout
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = KnockoutChecker::new();
        let body1 = r#"function(n,t,i){n[t]=i},e.version="2.1.0",e.exportSymbol("version",e.version),__RequestVerificationToken()"#;
        let url1 = "https://www.example.com/js/file.js";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "version=\"2.1.0\"",
            "Knockout",
            Some("2.1.0"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = KnockoutChecker::new();
        let body =
            r#"function(n,t,i){n[t]=i},e.version="2.2.0",e.exportSymbol("version",e.version),"#;
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
    fn comment_matches() {
        let checker = KnockoutChecker::new();
        let body1 = r#"// Knockout JavaScript library v2.1.0"#;
        let url1 = "https://www.example.com/that.jsp?abc=def";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Knockout JavaScript library v2.1.0",
            "Knockout",
            Some("2.1.0"),
            Some(url1),
        );
    }

    #[test]
    fn comment_doesnt_match() {
        let checker = KnockoutChecker::new();
        let body1 = r#"/*! Knockout 2.8.0"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = KnockoutChecker::new();
        let body1 = r#"// Knockout JavaScript library v3.1.7"#;
        let url1 = "https://www.example.com/j.js";
        let mut url_response_valid =
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
            "Knockout JavaScript library v3.1.7",
            "Knockout",
            Some("3.1.7"),
            Some(url1),
        );

        let body2 = r#"function(a1, c2, d3) { a[c] = d} ; a.version = "3.2.1", __RequestVerificationToken()"#;
        let url2 = "https://www.example.com/g.js";
        url_response_valid =
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
            "version = \"3.2.1\"",
            "Knockout",
            Some("3.2.1"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = KnockoutChecker::new();
        let body1 = r#"a.version = "3.2.1", __RequestVerificationToken()"#;
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
