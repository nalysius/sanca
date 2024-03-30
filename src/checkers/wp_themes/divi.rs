//! The Divi checker.
//! This module contains the checker used to determine if Divi is
//! used by the asset.

use std::collections::HashMap;

use crate::checkers::HttpChecker;
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct DiviChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> DiviChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: /*!
        //      Theme Name: Divi
        //      Theme URI: http://www.elegantthemes.com/gallery/divi/
        //      Version: 4.23.0
        //      Description: Smart. Flexible. Beautiful. Divi is the most powerful theme in our collection.
        //
        // (?s) means . matches also newline
        let source_code_regex =
            Regex::new(r#"(?s)/*!.+Theme\s+Name:\s+Divi\n.+(?P<wholematch>Version:\s+(?P<version1>\d+\.\d+(\.\d+)?))"#).unwrap();

        regexes.insert("http-body-source", source_code_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running DiviChecker::check_http_body() on {}",
            url_response.url
        );

        if url_response
            .url
            .contains("/wp-content/themes/Divi/style.css")
        {
            let caps_result = self
                .regexes
                .get("http-body-source")
                .expect("Regex \"http-body-source\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Divi/http-body-source matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                30,
                30,
                "Divi",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
            }
        }
        None
    }
}

impl<'a> HttpChecker for DiviChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running DiviChecker::check_http()");
        let mut findings = Vec::new();
        for url_response in data {
            // Search on the main page only
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }
            let response = self.check_http_body(&url_response);
            if response.is_some() {
                findings.push(response.unwrap());
            }
        }
        return findings;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::WPTDivi
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = DiviChecker::new();
        let body1 = r#"/*!
        Theme Name: Divi
        Theme URI: http://www.elegantthemes.com/gallery/divi/
        Version: 4.23.0
        Description: Smart. Flexible. Beautiful. Divi is the most powerful theme in our collection."#;
        let url1 = "https://www.example.com/blog/wp-content/themes/Divi/style.css";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Version: 4.23.0",
            "Divi",
            Some("4.23.0"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = DiviChecker::new();
        let body = r#"Divi can be found in version: 4.23.1"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/wp-content/themes/other-theme/style.css",
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
        let checker = DiviChecker::new();
        let body1 = r#"/*!
        Theme Name: Divi
        Theme URI: http://www.elegantthemes.com/gallery/divi/
        Version: 4.23.1
        Description: Smart. Flexible. Beautiful. Divi is the most powerful theme in our collection."#;
        let url1 = "https://www.example.com/wp-content/themes/Divi/style.css";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/invalid/path.php",
            HashMap::new(),
            "nothing to see in body",
            UrlRequestType::Default,
            200,
        );
        let findings = checker.check_http(&[url_response_invalid, url_response_valid]);
        assert_eq!(1, findings.len());
        check_finding_fields(
            &findings[0],
            "Version: 4.23.1",
            "Divi",
            Some("4.23.1"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = DiviChecker::new();
        let body1 = r#"/*!
        Theme Name: AnotherTheme
        Theme URI: http://www.elegantthemes.com/gallery/divi/
        Version: 4.23.2
        Description: Smart. Flexible. Beautiful. Divi is the most powerful theme in our collection."#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"How to install Divi 4.23.2"#;
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
