//! The Yoast SEO checker.
//! This module contains the checker used to determine if Yoast SEO is
//! used by the asset.
//! https://wordpress.org/plugins/wordpress-seo/

use std::collections::HashMap;

use crate::checkers::{Checker, HttpChecker};
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct YoastSEOChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> YoastSEOChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: <!-- This site is optimized with the Yoast SEO plugin v20.11 - https://yoast.com/wordpress/plugins/seo/ -->
        let source_code_regex = Regex::new(
            r#"(?P<wholematch><!-- This site is optimized with the Yoast SEO plugin v(?P<version1>\d+\.\d+(\.\d+)?) - https://yoast.com/wordpress/plugins/seo/ -->)"#,
        )
        .unwrap();

        // Example: Stable tag: 20.11
        let readme_regex =
            Regex::new(r#"(?P<wholematch>Stable tag: (?P<version1>\d+\.\d+(\.\d+)?))"#).unwrap();

        regexes.insert("http-body-source", (source_code_regex, 65, 10));
        regexes.insert("http-body-readme", (readme_regex, 30, 30));
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running YoastSEOChecker::check_http_body() on {}",
            url_response.url
        );

        let body_source_regex_params = self
            .regexes
            .get("http-body-source")
            .expect("Regex YoastSEO/http-body-source not found");
        let (regex_source, keep_left_source, keep_right_source) = body_source_regex_params;
        let caps_result = regex_source.captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex YoastSEO/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                Some(url_response),
                keep_left_source.to_owned(),
                keep_right_source.to_owned(),
                Technology::WPPYoastSEO,
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        if url_response
            .url
            .contains("/wp-content/plugins/wordpress-seo/readme.txt")
        {
            let body_readme_regex_params = self
                .regexes
                .get("http-body-readme")
                .expect("Regex YoastSEO/http-body-readme not found");
            let (regex_readme, keep_left_readme, keep_right_readme) = body_readme_regex_params;
            let caps_result = regex_readme.captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex YoaseSEO/http-body-readme matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                Some(url_response),
                keep_left_readme.to_owned(),
                keep_right_readme.to_owned(),
                Technology::WPPYoastSEO,
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
            }
        }

        None
    }
}

impl<'a> Checker for YoastSEOChecker<'a> {}

impl<'a> HttpChecker for YoastSEOChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running YoastSEOChecker::check_http()");
        let mut findings = Vec::new();
        for url_response in data {
            // Search on the main pages only
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
        Technology::WPPYoastSEO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = YoastSEOChecker::new();
        let body1 = r#"<b>BOLD</b><!-- This site is optimized with the Yoast SEO plugin v20.11 - https://yoast.com/wordpress/plugins/seo/ -->"#;
        let url1 = "https://www.example.com/blog/";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Yoast SEO plugin v20.11",
            Technology::WPPYoastSEO,
            Some("20.11"),
            Some(url1),
        );

        let body2 = r#"=== Yoast SEO ===
        Contributors: yoast, joostdevalk, tdevalk
        Donate link: https://yoa.st/1up
        License: GPLv3
        License URI: http://www.gnu.org/licenses/gpl.html
        Tags: SEO, XML sitemap, Content analysis, Readability, Schema
        Tested up to: 6.4
        Stable tag: 21.6
        Requires PHP: 7.2.5"#;
        let url2 = "https://www.example.com/blog/wp-content/plugins/wordpress-seo/readme.txt";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Stable tag: 21.6",
            Technology::WPPYoastSEO,
            Some("21.6"),
            Some(url2),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = YoastSEOChecker::new();
        let body = r#"<i>This</i> website is using Yoast SEO plugin v20.10"#;
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
        let checker = YoastSEOChecker::new();
        let body1 = r#"<title>Title</title><!-- This site is optimized with the Yoast SEO plugin v20.01 - https://yoast.com/wordpress/plugins/seo/ --><img src="a.jpg" />"#;
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
            "Yoast SEO plugin v20.01",
            Technology::WPPYoastSEO,
            Some("20.01"),
            Some(url1),
        );

        let body2 = r#"=== Yoast SEO ===
        Contributors: yoast, joostdevalk, tdevalk
        Donate link: https://yoa.st/1up
        License: GPLv3
        License URI: http://www.gnu.org/licenses/gpl.html
        Tags: SEO, XML sitemap, Content analysis, Readability, Schema
        Tested up to: 6.4
        Stable tag: 20.5
        Requires PHP: 7.2.5"#;
        let url2 = "https://www.example.com/wp-content/plugins/wordpress-seo/readme.txt";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http(&[url_response_valid]);
        assert_eq!(1, finding.len());
        check_finding_fields(
            &finding[0],
            "Stable tag: 20.5",
            Technology::WPPYoastSEO,
            Some("20.5"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = YoastSEOChecker::new();
        let body1 = r#"Marker is &lt;!-- This site is optimized with the Yoast SEO plugin v20.11 - https://yoast.com/wordpress/plugins/seo/ --&gt;"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"How to install Yoast SEO v20.0"#;
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
