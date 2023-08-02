//! The GSAP checker.
//! This module contains the checker used to determine if GSAP is
//! used by the asset.

use std::collections::HashMap;

use super::HttpChecker;
use crate::models::{Finding, Technology, UrlResponse};
use log::{info, trace};
use regex::Regex;

/// The checker
pub struct GsapChecker<'a> {
    /// The regexes used to recognize the technology
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> GsapChecker<'a> {
    /// Creates the checker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: /*!
        //           * PixiPlugin 3.11.1
        //
        // or
        //
        // gsap)&&f.r[...],i,c,y,v,h,r={version:"3.11.1"
        let gsap_plugins = "CSSRulePlugin|CustomEase|Draggable|EaselPlugin|EasePack|Flip|GSAP|MotionPathPlugin|Observer|PixiPlugin|ScrollToPlugin|ScrollTrigger|TextPlugin";
        let comment_regex = Regex::new(&format!(
            r"^\s+\*\s+(?P<wholematch>({})\s+(?P<version>\d+\.\d+\.\d+))",
            gsap_plugins
        ))
        .unwrap();

        let body_minified_regex =
            Regex::new(r#"(?P<wholematch>gsap.+version[=:]['"](?P<version>\d+\.\d+\.\d+)['"])"#)
                .unwrap();

        regexes.insert("http-body-comment", comment_regex);
        regexes.insert("http-body-minified", body_minified_regex);
        Self { regexes: regexes }
    }

    /// Checks in HTTP response body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running GsapChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-comment")
            .expect("Regex \"http-body-comment\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex GSAP/http-body matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 30, 30, "GSAP", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }

        let caps_result = self
            .regexes
            .get("http-body-minified")
            .expect("Regex \"http-body-minified\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex GSAP/http-body-minified matches");
            let caps = caps_result.unwrap();
            return Some(self.extract_finding_from_captures(caps, url_response, 10, 30, "GSAP", "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" at this url: $url_of_finding$"));
        }
        None
    }
}

impl<'a> HttpChecker for GsapChecker<'a> {
    /// Check for a HTTP scan.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        for url_response in data {
            let response = self.check_http_body(&url_response);
            if response.is_some() {
                return response;
            }
        }
        return None;
    }

    /// The technology supported by the checker
    fn get_technology(&self) -> Technology {
        Technology::Gsap
    }
}
