//! The TYPO3 checker.
//! This module contains the checker used to determine if TYPO3 is
//! used by the asset.
//! https://typo3.org

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::reqres::{UrlRequestType, UrlResponse};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct Typo3Checker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> Typo3Checker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: "typo3/cms-core": "x.y.z"
        let composer_regex = Regex::new(
            r#"(?P<wholematch>"typo3\/cms-core" *: *"(?P<version1>\d+\.\d+\.\d+(\.\d+)?)")"#,
        )
        .unwrap();

        // Example: <meta name="generator" content="TYPO3 4.7 CMS">
        let source_code_regex = Regex::new(
            r#"(?P<wholematch><meta\s+name\s*=\s*['"][Gg]enerator['"]\s+content\s*=\s*['"]TYPO3 (?P<version1>\d+\.\d+(\.\d+)?)\s+CMS['"]\s*/?>)"#,
        )
        .unwrap();

        regexes.insert("http-body-composer", (composer_regex, 30, 30));
        regexes.insert("http-body-source", (source_code_regex, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running Typo3Checker::check_http_body() on {}",
            url_response.url
        );

        let body_source_regex_params = self
            .regexes
            .get("http-body-source")
            .expect("Regex TYPO3/http-body-source not found");
        let (regex_source, keep_left_source, keep_right_source) = body_source_regex_params;
        let caps_result = regex_source.captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex TYPO3/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                Some(url_response),
                keep_left_source.to_owned(),
                keep_right_source.to_owned(),
                Technology::Typo3,
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$")
            );
        }

        // This regex is not restrictive and could generate false positive
        // results, so restrict its usage on URLs containing composer.json
        if url_response.url.contains("/composer.json") {
            let body_composer_regex_params = self
                .regexes
                .get("http-body-composer")
                .expect("Regex TYPO3/http-body-composer not found");
            let (regex_composer, keep_left_composer, keep_right_composer) =
                body_composer_regex_params;
            let caps_result = regex_composer.captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex TYPO3/http-body-composer matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left_composer.to_owned(),
		    keep_right_composer.to_owned(),
		    Technology::Typo3,
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }

        None
    }
}

impl<'a> Checker for Typo3Checker<'a> {}

impl<'a> HttpChecker for Typo3Checker<'a> {
    /// Check for a HTTP scan.
    ///
    /// Returns only one finding, otherwise findings would be duplicated each
    /// time it's found.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running Typo3Checker::check_http()");

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
        Technology::Typo3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;

    #[test]
    fn source_code_matches() {
        let checker = Typo3Checker::new();
        let url = "http://www.example.com/typo3/composer.json";
        let body1 = r#""typo3/cms-core": "4.7.1""#;
        let url_response_valid =
            UrlResponse::new(url, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "\"4.7.1",
            Technology::Typo3,
            Some("4.7.1"),
            Some(url),
        );

        let url2 = "http://www.example.com/";
        let body2 = r#"<title>test</title><meta name = "generator" content="TYPO3 4.7 CMS">"#;
        let url_response_valid1 =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "4.7",
            Technology::Typo3,
            Some("4.7"),
            Some(url2),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = Typo3Checker::new();
        let body = r#"typo3/cms-core: 3.2.1"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/about.php?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());

        let url2 = "http://www.example.com/";
        let body2 = r#"&lt;title&gt;test&lt;/title&gt;&lt;meta name="Generator"  content ="TYPO3 4.7 CMS" /&gt;"#;
        let url_response_valid1 =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid1);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = Typo3Checker::new();
        let body1 = r#""typo3/cms-core" : "4.7.2.8""#;
        let url1 = "https://www.example.com/site/typo3/composer.json";
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
            "\"4.7.2.8",
            Technology::Typo3,
            Some("4.7.2.8"),
            Some(url1),
        );

        let url2 = "http://www.example.com/";
        let body2 = r#"<title>test</title><meta name = "generator" content="TYPO3 4.7 CMS">"#;
        let url_response_valid1 =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http(&[url_response_valid1]);
        assert_eq!(1, finding.len());
        check_finding_fields(
            &finding[0],
            "4.7",
            Technology::Typo3,
            Some("4.7"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = Typo3Checker::new();
        let body1 = r#"About TYPO3 4.7.11"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );

        let body2 = "<h3>TYPO3/4.3.2</h3>";
        let url_response_invalid2 = UrlResponse::new(
            "https://www.example.com/not-404-page",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid1, url_response_invalid2]);
        assert!(findings.is_empty());

        let url3 = "http://www.example.com/";
        let body3 =
            r#"&lt;title>test&lt;/title>&lt;meta name= "Generator" content="TYPO3 4.7 CMS"/>"#;
        let url_response_valid3 =
            UrlResponse::new(url3, HashMap::new(), body3, UrlRequestType::Default, 200);
        let finding = checker.check_http(&[url_response_valid3]);
        assert!(finding.is_empty());
    }
}
