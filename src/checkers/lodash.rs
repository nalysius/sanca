//! The Lodash checker.
//! This module contains the checker used to determine if Lodash is
//! used by the asset.
//! https://lodash.com

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct LodashChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> LodashChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example:
        //
        //  [...]
        // lodash[...],An.VERSION="4.17.15"
        //
        let body_regex = Regex::new(
            r#"lodash.+(?P<wholematch>(var )?VERSION ?= ?['"](?P<version1>\d+\.\d+\.\d+)['"])[;,]?"#,
        )
        .unwrap();

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
        //
        // Note: (?s) means . matches also newlines
        let body_not_minified = Regex::new(r#"(?s)\*\s+@license.\s+\*\s+(?P<wholematch>Lodash.+var\s+VERSION\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"]);"#)
        .unwrap();

        let body_minified_regex = Regex::new(
            r#"(?P<wholematch>VERSION\s*=\s*[a-zA-Z0-9]+[,;].+[a-zA-Z0-9]+=['"](?P<version1>\d+\.\d+\.\d+)['"]).+lodash_placeholder"#,
        )
        .unwrap();

        let body_minified_regex_alternative = Regex::new(
            r#"(?s)(?P<wholematch>[a-zA-z0-9]+\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"][,;].+lodash_placeholder.+VERSION\s*=\s*[a-zA-Z0-9]+)"#,
        )
        .unwrap();

        let body_comment_compat =
            Regex::new(r#"\s*\*\s*(?P<wholematch>Lo-Dash (?P<version1>\d+\.\d+\.\d+))"#).unwrap();

        regexes.insert("http-body", (body_regex, 30, 30));
        regexes.insert("http-body-minified", (body_minified_regex, 30, 30));
        regexes.insert(
            "http-body-minified-alternative",
            (body_minified_regex_alternative, 10, 30),
        );
        regexes.insert("http-body-not-minified", (body_not_minified, 6, 15));
        regexes.insert("http-body-comment-compat", (body_comment_compat, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running LodashChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);

            if caps_result.is_some() {
                info!("Regex Lodash/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    Technology::Lodash,
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for LodashChecker<'a> {}

impl<'a> HttpChecker for LodashChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running LodashChecker::check_http()");
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
        Technology::Lodash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = LodashChecker::new();
        let body1 = r#"var a = 42;lodash.c();var VERSION= '4.17.15';var b = 1;"#;
        let url1 = "https://www.example.com/js/file.js";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "VERSION= '4.17.15'",
            Technology::Lodash,
            Some("4.17.15"),
            Some(url1),
        );

        let body2 = r#"a.b=10;VERSION = abc;a.c();var v="4.17.15"; a.lodash_placeholder"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "v=\"4.17.15\"",
            Technology::Lodash,
            Some("4.17.15"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = LodashChecker::new();
        let body = r#"var f = "LodashPlaceholder"; VERSION="4.7.7";"#;
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
        let checker = LodashChecker::new();
        let body1 = r#"var a = 42;lodash.x = 0;var VERSION = "4.17.15";var b = 1;"#;
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
            "VERSION = \"4.17.15\"",
            Technology::Lodash,
            Some("4.17.15"),
            Some(url1),
        );

        let body2 = r#"a.e1(); VERSION=abc;a.c_1 = "10";var v="4.17.15"; a.lodash_placeholder;"#;
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
            "v=\"4.17.15\"",
            Technology::Lodash,
            Some("4.17.15"),
            Some(url2),
        );
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
