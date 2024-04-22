//! The Horde checker.
//! This module contains the checker used to determine if Horde is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct HordeChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> HordeChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example:  <span class="smallheader">Horde 5.2.18</span>
        let body_regex = Regex::new(r#"<span\s+class\s*=\s*['"]smallheader['"]\s*>\s*(?P<wholematch>Horde\s+(?P<version1>\d+\.\d+\.\d+))"#).unwrap();

        regexes.insert("http-body", (body_regex, 30, 30));

        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running HordeChecker::check_http_body() on {}",
            url_response.url
        );

        if !url_response.url.contains("/horde/services/help/") {
            return None;
        }

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex Horde/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    "Horde",
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for HordeChecker<'a> {}

impl<'a> HttpChecker for HordeChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running HordeChecker::check_http()");
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
        Technology::Horde
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = HordeChecker::new();
        let body1 = r#" <span class="smallheader">Horde 5.2.18</span>"#;
        let url1 = "https://www.example.com/horde/services/help/index.php?module=horde&show=menu";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Horde 5.2.18",
            "Horde",
            Some("5.2.18"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = HordeChecker::new();
        let body = r#"<span class="bigheader">Horde 1.2.3</span>"#;
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
        let checker = HordeChecker::new();
        let body1 = r#" <span  class = 'smallheader'> Horde 5.1.3</span>"#;
        let url1 =
            "https://www.example.com/dir/horde/services/help/index.php?module=horde&show=menu";
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
            "Horde 5.1.3",
            "Horde",
            Some("5.1.3"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = HordeChecker::new();
        let body1 = r#"<h1>Horde 4.0.19 is not installed here.</h1>"#;
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
