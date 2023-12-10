//! The All In One SEO checker.
//! This module contains the checker used to determine if All In One is
//! used by the asset.

use std::collections::HashMap;

use crate::checkers::HttpChecker;
use crate::models::reqres::UrlRequestType;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct AllInOneSEOChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> AllInOneSEOChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();

        // Example: <!-- All in One SEO Pro 4.5.1.1 - aioseo.com -->
        let source_code_regex = Regex::new(
            r#"(?P<wholematch><!-- All in One SEO (Pro )?(?P<version>\d+\.\d+(\.\d+(\.\d)?)?) - aioseo.com -->)"#,
        )
        .unwrap();

        // Example: Stable tag: 4.4.2.1
        let readme_regex =
            Regex::new(r#"(?P<wholematch>Stable tag: (?P<version>\d+\.\d+(\.\d+(\.\d)?)?))"#)
                .unwrap();

        // Example: <meta name="generator" content="All in One SEO Pro (AIOSEO) 4.5.1.1" />
        let body_meta_regex = Regex::new(r#"(?P<wholematch><meta\s+name\s*=\s*['"][Gg]enerator['"]\s+content\s*=\s*['"]All in One SEO (Pro )?\(AIOSEO\) (?P<version>\d+\.\d+(\.\d+(\.\d)?)?)['"]\s*\/>)"#).unwrap();

        regexes.insert("http-body-source", source_code_regex);
        regexes.insert("http-body-meta", body_meta_regex);
        regexes.insert("http-body-readme", readme_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running AllInOneSEOChecker::check_http_body() on {}",
            url_response.url
        );

        // Search in HTML comment
        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex AllInOneSEO/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                65,
                10,
                "AllInOneSEO",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        // Search in <meta> tag
        let caps_result = self
            .regexes
            .get("http-body-meta")
            .expect("Regex \"http-body-meta\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex AllInOneSEO/http-body-meta matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                65,
                30,
                "AllInOneSEO",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        // Search in the readme.txt
        if url_response
            .url
            .contains("/wp-content/plugins/all-in-one-seo-pack/readme.txt")
        {
            let caps_result = self
                .regexes
                .get("http-body-readme")
                .expect("Regex \"http-body-readme\" not found.")
                .captures(&url_response.body);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex AllInOneSEO/http-body-readme matches");
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                30,
                30,
                "AllInOneSEO",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
            }
        }

        None
    }
}

impl<'a> HttpChecker for AllInOneSEOChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running AllInOneSEOChecker::check_http()");
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
        Technology::WPPAllInOneSEO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = AllInOneSEOChecker::new();
        // Check the HTML comment
        let body1 = r#"<b>BOLD</b><!-- All in One SEO Pro 4.3.1.1 - aioseo.com -->"#;
        let url1 = "https://www.example.com/blog/";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "All in One SEO Pro 4.3.1.1",
            "AllInOneSEO",
            Some("4.3.1.1"),
            Some(url1),
        );

        // Check the readme.txt
        let body2 = r#"=== All in One SEO – Best WordPress SEO Plugin – Easily Improve SEO Rankings & Increase Traffic ===
        Contributors: aioseo, smub, benjaminprojas
        Tags: SEO, Google Search Console, XML Sitemap, meta description, schema, meta title
        Tested up to: 6.4.2
        Requires at least: 4.9
        Requires PHP: 7.0
        Stable tag: 4.5.1.1"#;
        let url2 = "https://www.example.com/blog/wp-content/plugins/all-in-one-seo-pack/readme.txt";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "Stable tag: 4.5.1.1",
            "AllInOneSEO",
            Some("4.5.1.1"),
            Some(url2),
        );

        // Check the <meta> tag
        let body3 = r#"<meta name="generator" content="All in One SEO Pro (AIOSEO) 4.5.1.1" />"#;
        let url3 = "https://www.example.com/blog/";
        let url_response_valid =
            UrlResponse::new(url3, HashMap::new(), body3, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "All in One SEO Pro (AIOSEO) 4.5.1.1",
            "AllInOneSEO",
            Some("4.5.1.1"),
            Some(url3),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = AllInOneSEOChecker::new();
        let body = r#"<i>This</i> website is using All In One SEO plugin 4.6.2.9"#;
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
        let checker = AllInOneSEOChecker::new();
        // Check the HTML comment
        let body1 = r#"<title>Title</title><!-- All in One SEO 4.5.1.1 - aioseo.com --><img src="a.jpg" />"#;
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
            "All in One SEO 4.5.1.1",
            "AllInOneSEO",
            Some("4.5.1.1"),
            Some(url1),
        );

        // Check the readme.txt
        let body2 = r#"=== All in One SEO – Best WordPress SEO Plugin – Easily Improve SEO Rankings & Increase Traffic ===
        Contributors: aioseo, smub, benjaminprojas
        Tags: SEO, Google Search Console, XML Sitemap, meta description, schema, meta title, rich snippets, woocommerce seo, local seo, open graph, google news sitemap, video sitemap, robots.txt, seo audit, content analysis, seo plugin, redirection
        Tested up to: 6.4.2
        Requires at least: 4.9
        Requires PHP: 7.0
        Stable tag: 4.5.2.1"#;
        let url2 = "https://www.example.com/wp-content/plugins/all-in-one-seo-pack/readme.txt";
        let url_response_valid =
            UrlResponse::new(url2, HashMap::new(), body2, UrlRequestType::Default, 200);
        let finding = checker.check_http(&[url_response_valid]);
        assert_eq!(1, finding.len());
        check_finding_fields(
            &finding[0],
            "Stable tag: 4.5.2.1",
            "AllInOneSEO",
            Some("4.5.2.1"),
            Some(url2),
        );

        // Check the <meta> tag
        // Check the <meta> tag
        let body3 = r#"<meta name="Generator" content="All in One SEO (AIOSEO) 4.5.1.1" />"#;
        let url3 = "https://www.example.com/blog/";
        let url_response_valid =
            UrlResponse::new(url3, HashMap::new(), body3, UrlRequestType::Default, 200);
        let finding = checker.check_http(&[url_response_valid]);
        assert_eq!(1, finding.len());
        check_finding_fields(
            &finding[0],
            "All in One SEO (AIOSEO) 4.5.1.1",
            "AllInOneSEO",
            Some("4.5.1.1"),
            Some(url3),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = AllInOneSEOChecker::new();
        let body1 = r#"Marker is &lt;!!-- All in One SEO Pro 4.5.1.1 - aioseo.com --&gt;"#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"How to install All In One SEO 4.5.6.7"#;
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
