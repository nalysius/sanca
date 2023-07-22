//! The OS checker.
//! This module contains the checker used to determine if the OS
//! can be identified.

use std::collections::HashMap;

use super::{HttpChecker, TcpChecker};
use crate::models::{Finding, Technology};
use regex::{Match, Regex};

/// The OS checker
pub struct OSChecker<'a> {
    /// The regexes used to recognize the OS
    regexes: HashMap<&'a str, Regex>,
}

impl<'a> OSChecker<'a> {
    /// Creates a new OSChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: SSH-2.0-OpenSSH_6.7p1 Debian-5
        // SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2
        // TODO: use the deb8u2 part.
        // Also use the OpenSSH version & the OS name to determine which version
        // of OS is used
        let openssh_regex =
            Regex::new(r"^SSH-\d+\.\d+-OpenSSH_\d+\.\d+([a-z]\d+)?( (?P<os>[a-zA-Z0-0]+))?")
                .unwrap();
        // Example: Apache/2.4.52 (Debian)
        let header_regex =
            Regex::new(r"^(Apache|nginx)\/(?P<version>\d+\.\d+\.\d+)( \((?P<osname>[^\)]+)\))")
                .unwrap();

        regexes.insert("openssh-banner", openssh_regex);
        regexes.insert("http-header", header_regex);
        OSChecker { regexes: regexes }
    }
}

impl<'a> TcpChecker for OSChecker<'a> {
    /// Check what OS is running on the asset.
    /// It looks for the OpenSSH banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        // For each item, check if it's an OpenSSH banner
        for item in data {
            let caps_result = self
                .regexes
                .get("openssh-banner")
                .expect("Regex \"openssh-banner\" not found.")
                .captures(item);
            // The regex matches
            if caps_result.is_some() {
                let caps = caps_result.unwrap();
                let os: Option<Match> = caps.name("os");

                // The OS has been found
                if os.is_some() {
                    let os_evidence_text = format!(
                        "The operating system {} has been identified using the banner presented by OpenSSH.",
                        os.unwrap().as_str()
                    );
                    return Some(Finding::new("OS", None, item, &os_evidence_text, None));
                }
            }
        }
        return None;
    }

    /// This checker supports the OS
    fn get_technology(&self) -> Technology {
        Technology::OS
    }
}

impl<'a> HttpChecker for OSChecker<'a> {
    fn check_http(&self, data: &[crate::models::UrlResponse]) -> Option<Finding> {
        for url_response in data {
            let headers_to_check =
                url_response.get_headers(&vec!["Server".to_string(), "X-powered-by".to_string()]);

            // Check in the headers to check that were present in this UrlResponse
            for (header_name, header_value) in headers_to_check {
                let caps_result = self
                    .regexes
                    .get("http-header")
                    .expect("Regex \"http-header\" not found.")
                    .captures(&header_value);
                // The regex matches
                if caps_result.is_some() {
                    let caps = caps_result.unwrap();
                    let osname = caps["osname"].to_string();
                    let evidence = &format!("{}: {}", header_name, header_value);
                    let evidence_text = format!(
                        "The operating system {} has been identified using the HTTP header \"{}\" returned at the following URL: {}",
                        osname,
                        evidence,
                        url_response.url,
                    );
                    return Some(Finding::new(
                        "OS",
                        Some(&osname),
                        evidence,
                        &evidence_text,
                        Some(&url_response.url),
                    ));
                }
            }
        }
        None
    }

    /// This checker supports the OS
    fn get_technology(&self) -> Technology {
        Technology::OS
    }
}
