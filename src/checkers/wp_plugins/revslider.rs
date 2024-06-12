//! The RevSlider checker.
//! This module contains the checker used to determine if RevSlider is
//! used by the asset.
//! https://www.sliderrevolution.com/

use std::collections::HashMap;

use crate::checkers::{Checker, HttpChecker};
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct RevSliderChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> RevSliderChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: <meta name="generator" content="Powered by Slider Revolution 6.5.11 - responsive, Mobile-Friendly Slider Plugin for WordPress with comfortable drag and drop interface." />
        let source_meta_regex = Regex::new(
            r#"(?P<wholematch><meta\s+name="generator"\s+content="Powered by Slider Revolution (?P<version1>\d+\.\d+\.\d+(\.\d+)?) - )[^"]+""#,
        )
            .unwrap();

        let source_comment_regex = Regex::new(
            r#"(?P<wholematch><!--\s+START\s+REVOLUTION\s+SLIDER\s+(?P<version1>\d+\.\d+\.\d+(\.\d+)?)( fullwidth mode)?\s+-->)"#,
        )
            .unwrap();

        regexes.insert("http-body-meta", (source_meta_regex, 30, 30));
        regexes.insert("http-body-comment", (source_comment_regex, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running RevSliderChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex RevSlider/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                    caps,
                    Some(url_response),
                    keep_left.to_owned(),
                    keep_right.to_owned(),
                    "RevSlider",
                    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for RevSliderChecker<'a> {}

impl<'a> HttpChecker for RevSliderChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running RevSliderChecker::check_http()");
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
        Technology::WPPRevSlider
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = RevSliderChecker::new();
        let body1 = r#"<b>BOLD</b><meta name="generator" content="Powered by Slider Revolution 6.5.11 - responsive, Mobile-Friendly Slider Plugin for WordPress with comfortable drag and drop interface." />"#;
        let url1 = "https://www.example.com/blog/";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Slider Revolution 6.5.11",
            "RevSlider",
            Some("6.5.11"),
            Some(url1),
        );

        let body2 = r#"<div></div><!-- START REVOLUTION SLIDER 5.4.8.3 fullwidth mode --> <hr />"#;
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "REVOLUTION SLIDER 5.4.8.3",
            "RevSlider",
            Some("5.4.8.3"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = RevSliderChecker::new();
        let body = r#"<i>This</i> website is using RevSlider plugin 6.5.10"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());

        let body2 = r#"&lt;!-- START REVOLUTION SLIDER 5.4.8.3 fullwidth mode --&gt;"#;
        let url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body2,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = RevSliderChecker::new();
        let body1 = r#"<title>Title</title><meta name="generator" content="Powered by Slider Revolution 6.4.11 - responsive, Mobile-Friendly Slider Plugin for WordPress with comfortable drag and drop interface." /><img src="a.jpg" />"#;
        let url1 = "https://www.example.com/";
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
            "Slider Revolution 6.4.11",
            "RevSlider",
            Some("6.4.11"),
            Some(url1),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = RevSliderChecker::new();
        let body1 = r#"Marker is &lt;meta name="generator" content="Powered by Slider Revolution 6.5.11 - responsive, Mobile-Friendly Slider Plugin for WordPress with comfortable drag and drop interface." /&gt;"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"How to install Slider Revolution 6.4.10"#;
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
