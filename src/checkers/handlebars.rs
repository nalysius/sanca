//! The Handlebars checker.
//! This module contains the checker used to determine if Handlebars is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct HandlebarsChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> HandlebarsChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /**!
        //          @license
        //          handlebars v4.7.7
        //
        // OR
        //
        // /*!
        //  handlebars v2.0.0
        let comment_regex = Regex::new(
            r"\/\*\*?![\s\*]+(@license)?\s+(?P<wholematch>handlebars (v(?P<version1>\d\.\d\.\d)))",
        )
        .unwrap();

        // Example: HandlebarsEnvironment;[...]b="4.7.7";An.VERSION=b;
        let source_code_regex = Regex::new(r#"(?P<wholematch>HandlebarsEnvironment;.*[a-zA-Z0-9]+\s*=\s*"(?P<version1>\d+\.\d+\.\d+)";[a-zA-Z0-9]+\.VERSION=[a-zA-Z0-9]+;)"#).unwrap();

        // Example: VERSION="2.0.0";__exports__.VERSION=VERSION[...]HandlebarsEnvironment
        let source_code_regex_alternative = Regex::new(r#"(?P<wholematch>VERSION\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"]+[,;]__exports__\.VERSION\s*=\s*VERSION.+HandlebarsEnvironment)"#).unwrap();

        // Example: HandlebarsEnvironment;[...]b="4.7.7";An.VERSION=b;
        let source_code_regex_alternative_2 = Regex::new(r#"(?P<wholematch>VERSION\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"];.+HandlebarsEnvironment)"#).unwrap();

        regexes.insert("http-body-comment", comment_regex);
        regexes.insert("http-body-source", source_code_regex);
        regexes.insert(
            "http-body-source-alternative",
            source_code_regex_alternative,
        );
        regexes.insert(
            "http-body-source-alternative-2",
            source_code_regex_alternative_2,
        );
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running HandlebarsChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Handlebars/http-body-comment matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                40,
                40,
                "Handlebars",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        let caps_result = self
            .regexes
            .get("http-body-source")
            .expect("Regex \"http-body-source\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Handlebars/http-body-source matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                30,
                30,
                "Handlebars",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        let caps_result = self
            .regexes
            .get("http-body-source-alternative")
            .expect("Regex \"http-body-source-alternative\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Handlebars/http-body-source-alternative matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                30,
                30,
                "Handlebars",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        let caps_result = self
            .regexes
            .get("http-body-source-alternative-2")
            .expect("Regex \"http-body-source-alternative-2\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex Handlebars/http-body-source-alternative-2 matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(
                caps,
                url_response,
                30,
                30,
                "Handlebars",
                "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
            ));
        }

        None
    }
}

impl<'a> HttpChecker for HandlebarsChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running HandlebarsChecker::check_http()");
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
        Technology::Handlebars
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = HandlebarsChecker::new();
        let body1 = r#"start.HandlebarsEnvironment;a.b = 2;c="4.7.6";d.VERSION=c;e=mc2"#;
        let url1 = "https://www.example.com/js/file.js";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "c=\"4.7.6\"",
            "Handlebars",
            Some("4.7.6"),
            Some(url1),
        );

        let body2 = r#"this.ok= true;that().HandlebarsEnvironment;var1="4.7.7";v.VERSION=var1;"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "var1=\"4.7.7\"",
            "Handlebars",
            Some("4.7.7"),
            Some(url1),
        );

        let body3 = r#"VERSION="3.0.1";a=2;start.HandlebarsEnvironment;e=mc2"#;
        url_response_valid.body = body3.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "VERSION=\"3.0.1\"",
            "Handlebars",
            Some("3.0.1"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = HandlebarsChecker::new();
        let body = r#"var f = "HandlebarsEnvironment"; VERSION="4.7.7";"#;
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
        let checker = HandlebarsChecker::new();
        let body1 = r#"/**! * @license handlebars v4.7.7"#;
        let url1 = "https://www.example.com/that.jsp?abc=def";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "handlebars v4.7.7",
            "Handlebars",
            Some("4.7.7"),
            Some(url1),
        );

        let body2 = "/**!
        * @license handlebars v4.7.7";
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "handlebars v4.7.7",
            "Handlebars",
            Some("4.7.7"),
            Some(url1),
        );
    }

    #[test]
    fn comment_doesnt_match() {
        let checker = HandlebarsChecker::new();
        let body1 = r#"/**
        * Handlebars 1.2.3
        "#;
        let mut url_response_invalid = UrlResponse::new(
            "https://www.example.com/that.jsp?abc=def",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());

        let body2 = "// Handlebars v2";
        url_response_invalid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = HandlebarsChecker::new();
        let body1 = r#"/**!
        *
        *@license handlebars v4.7.7"#;
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
            "handlebars v4.7.7",
            "Handlebars",
            Some("4.7.7"),
            Some(url1),
        );

        let body2 = "/**!
        * 
        * @license handlebars v4.7.7";
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
            "handlebars v4.7.7",
            "Handlebars",
            Some("4.7.7"),
            Some(url2),
        );

        let body3 = r#"r.VERSION ='3.0.0';c=6;r.COMPILER_REVISION=c;y="[object Object]";return r.HandlebarsEnvironment=s"#;
        let url3 = "https://www.example.com/g.js";
        let url_response_valid =
            UrlResponse::new(url3, HashMap::new(), body3, UrlRequestType::JavaScript, 200);
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
            "VERSION ='3.0.0'",
            "Handlebars",
            Some("3.0.0"),
            Some(url2),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = HandlebarsChecker::new();
        let body1 = r#"Handlebars v4.4.7 is not installed here."#;
        let url_response_invalid1 = UrlResponse::new(
            "https://www.example.com/abc/def1",
            HashMap::new(),
            body1,
            UrlRequestType::Default,
            200,
        );
        let body2 = r#"It should not be detected as Handlebars"#;
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
