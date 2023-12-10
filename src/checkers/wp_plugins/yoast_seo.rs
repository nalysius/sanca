//! The Yoast SEO checker.
//! This module contains the checker used to determine if Yoast SEO is
//! used by the asset.

use std::collections::HashMap;

use crate::checkers::HttpChecker;
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct YoastSEOChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> YoastSEOChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: <!-- This site is optimized with the Yoast SEO plugin v20.11 - https://yoast.com/wordpress/plugins/seo/ -->
        let source_code_regex = Regex::new(
            r#"(?P<wholematch><!-- This site is optimized with the Yoast SEO plugin v(?P<version>\d+\.\d+(\.\d+)?) - https://yoast.com/wordpress/plugins/seo/ -->)"#,
        )
        .unwrap();

        // Example: Stable tag: 20.11
        let readme_regex =
            Regex::new(r#"(?P<wholematch>Stable tag: (?P<version>\d+\.\d+(\.\d+)?))"#).unwrap();

        regexes.insert("http-body-source", source_code_regex);
        regexes.insert("http-body-readme", readme_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running YoastSEOChecker::check_http_body() on {}",
            url_response.url
        );

        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex YoastSEO/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                65,
                10,
                "YoastSEO",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        if url_response
            .url
            .contains("/wp-content/plugins/wordpress-seo/readme.txt")
        {
            let caps_result = self
                .regexes
                .get("http-body-readme")
                .expect("Regex \"http-body-readme\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex YoaseSEO/http-body-readme matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                30,
                30,
                "YoastSEO",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
            }
        }

        None
    }
}

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
            "YoastSEO",
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
            "YoastSEO",
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
            "YoastSEO",
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
            "YoastSEO",
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
