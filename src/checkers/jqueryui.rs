//! The jQuery UI checker.
//! This module contains the checker used to determine if jQuery UI is
//! used by the asset.

use std::collections::HashMap;

use super::{Checker, HttpChecker};
use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct JQueryUIChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> JQueryUIChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /*! jQuery UI - v1.12.0 - 2016-07-08
        let comment_regex = Regex::new(r".*\/\*![\s\*]+(?P<wholematch>jQuery UI (JavaScript Library )?- (v@?(?P<version1>\d+\.\d+\.\d+)))( |)?").unwrap();

        // Example: class="ui-datepicker"; var a = 10;e.extends(e.ui, {version: "1.7.1", field: true})
        let body_minified_regex = Regex::new(r#"ui-datepicker.+(?P<wholematch>[a-zA-Z0-9]+\.ui,\s*\{\s*version\s*:\s*['"](?P<version1>\d+\.\d+\.\d+)['"])"#).unwrap();

        // t.ui=t.ui||{},t.ui.version="1.11.0";
        let body_minified_regex_alternative = Regex::new(r#"ui-datepicker.+(?P<wholematch>[a-zA-Z0-9]+\.ui\s*=\s*[a-zA-Z0-9]+\.ui\s*\|\|\s*\{\}\s*,\s*[a-zA-Z0-9]+\.ui\.version\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"])"#).unwrap();

        // ["jquery"], factory), $.ui.version="1.13.0";
        let body_minified_regex_alternative_1 = Regex::new(r#"j[Qq]uery.+(?P<wholematch>[a-zA-Z0-9\$]+\.ui\.version\s*=\s*['"](?P<version1>\d+\.\d+\.\d+)['"])"#).unwrap();

        // n.ui.version)||(n.extend(n.ui,{version:"1.10.0",
        let body_minified_regex_alternative_2 = Regex::new(r#"(?P<wholematch>[a-zA-Z0-9]+\.ui\.version\)?\s*\|\|\s*\(?[a-zA-Z0-9]+\.extend\([a-zA-Z0-9]+\.ui\s*,\s*\{version\s*:\s*['"](?P<version1>\d+\.\d+\.\d+)['"]).+ui-datepicker"#).unwrap();

        regexes.insert("http-body-comment", (comment_regex, 30, 30));
        regexes.insert("http-body-minified", (body_minified_regex, 30, 30));
        regexes.insert(
            "http-body-minified-alternative",
            (body_minified_regex_alternative, 30, 30),
        );
        regexes.insert(
            "http-body-minified-alternative-1",
            (body_minified_regex_alternative_1, 30, 30),
        );
        regexes.insert(
            "http-body-minified-alternative-2",
            (body_minified_regex_alternative_2, 30, 30),
        );
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running JQueryUIChecker::check_http_body() on {}",
            url_response.url
        );

        // Loop over each regex to try to detect the technology
        for (regex_name, (regex, keep_left, keep_right)) in &self.regexes {
            let caps_result = regex.captures(&url_response.body);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex JQueryUI/{} matches", regex_name);
                let caps = caps_result.unwrap();
                return Some(self.extract_finding_from_captures(
		    caps,
		    Some(url_response),
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    "jQueryUI",
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"
		));
            }
        }
        None
    }
}

impl<'a> Checker for JQueryUIChecker<'a> {}

impl<'a> HttpChecker for JQueryUIChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding> {
        trace!("Running JQueryUIChecker::check_http()");
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
        Technology::JQueryUI
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkers::check_finding_fields;
    use crate::models::reqres::UrlRequestType;

    #[test]
    fn source_code_matches() {
        let checker = JQueryUIChecker::new();
        let body1 =
            r#"class="ui-datepicker"; var a = 10;e.extends(e.ui, {version: "1.7.1", field: true})"#;
        let url1 = "https://www.example.com/js/file.js";
        let mut url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "version: \"1.7.1\"",
            "jQueryUI",
            Some("1.7.1"),
            Some(url1),
        );

        let body2 = r#"class="ui-datepicker"; var a = 10; myObject.extends(myObject.ui,{ version :'1.7.1'})"#;
        url_response_valid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "version :'1.7.1'",
            "jQueryUI",
            Some("1.7.1"),
            Some(url1),
        );

        let body3 = r#"var obj = "ui-datepicker"; myObject1.ui=myObject1.ui||{},myObject1.ui.version="1.12.0";"#;
        url_response_valid.body = body3.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "ui.version=\"1.12.0\"",
            "jQueryUI",
            Some("1.12.0"),
            Some(url1),
        );

        let body4 = r#"["jquery"], $.ui.version="1.13.0";"#;
        url_response_valid.body = body4.to_string();
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "$.ui.version=\"1.13.0\"",
            "jQueryUI",
            Some("1.13.0"),
            Some(url1),
        );
    }

    #[test]
    fn source_code_doesnt_match() {
        let checker = JQueryUIChecker::new();
        let body = r#"var class = "ui-datepicker"; var version="4.7.7";"#;
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
        let checker = JQueryUIChecker::new();
        let body1 = r#"/*! jQuery UI - v1.7.3 - 2016-07-08"#;
        let url1 = "https://www.example.com/that.jsp?abc=def";
        let url_response_valid =
            UrlResponse::new(url1, HashMap::new(), body1, UrlRequestType::Default, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "jQuery UI - v1.7.3",
            "jQueryUI",
            Some("1.7.3"),
            Some(url1),
        );
    }

    #[test]
    fn comment_doesnt_match() {
        let checker = JQueryUIChecker::new();
        let body1 = r#"/**
        * jQuery UI 1.2.3
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

        let body2 = "// jQuery UI v2";
        url_response_invalid.body = body2.to_string();
        let finding = checker.check_http_body(&url_response_invalid);
        assert!(finding.is_none());
    }

    #[test]
    fn finds_match_in_url_responses() {
        let checker = JQueryUIChecker::new();
        let body1 = r#"/*!
        *
        *jQuery UI - v1.7.7"#;
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
            "jQuery UI - v1.7.7",
            "jQueryUI",
            Some("1.7.7"),
            Some(url1),
        );

        let body2 = "/*! * jQuery UI - v1.6.1 - 2016-01-10";
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
            "jQuery UI - v1.6.1",
            "jQueryUI",
            Some("1.6.1"),
            Some(url2),
        );

        let body3 = r#"let class = 'ui-datepicker' ; myObject1.ui = myObject1.ui || {} , myObject1.ui.version = '1.12.1' ;"#;
        let url3 = "https://www.example.com/u.js";
        let url_response_valid =
            UrlResponse::new(url3, HashMap::new(), body3, UrlRequestType::JavaScript, 200);
        let finding = checker.check_http_body(&url_response_valid);
        assert!(finding.is_some());
        check_finding_fields(
            &finding.unwrap(),
            "ui.version = '1.12.1'",
            "jQueryUI",
            Some("1.12.1"),
            Some(url3),
        );
    }

    #[test]
    fn doesnt_find_match_in_url_responses() {
        let checker = JQueryUIChecker::new();
        let body1 = r#"jQuery UI v1.7.0 is not installed here."#;
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
