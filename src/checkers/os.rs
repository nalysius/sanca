//! The OS checker.
//! This module contains the checker used to determine if the OS
//! can be identified.

use std::collections::HashMap;

use super::{HttpChecker, TcpChecker};
use crate::models::{Finding, Technology, UrlRequestType, UrlResponse};
use log::{debug, info, trace};
use regex::Regex;

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
        let openssh_regex = Regex::new(
            r"^SSH-\d+\.\d+-OpenSSH_(?P<version>\d+\.\d+)([a-z]\d+)?( (?P<os>[a-zA-Z0-9]+))?",
        )
        .unwrap();
        // Example: Apache/2.4.52 (Debian)
        // TODO: if available, handle the OpenSSL version
        let header_regex = Regex::new(
            r"^(?P<software>Apache|nginx)\/(?P<version>\d+\.\d+\.\d+)( \((?P<os>[^\)]+)\))",
        )
        .unwrap();
        // Example: <address>Apache/2.4.52 (Debian) Server at localhost Port 80</address>
        // TODO: if available, handle the OpenSSL version
        let body_apache_regex = Regex::new(r"<address>(?P<wholematch>Apache\/(?P<version>\d+\.\d+\.\d+)( \((?P<os>[^\)]+)\)) Server at [a-zA-Z0-9-.]+ Port \d+)</address>").unwrap();

        // Example: <hr><center>nginx/1.22.3</center>
        let body_nginx_regex = Regex::new(r"<hr><center>(?P<wholematch>nginx(\/(?P<version>\d+\.\d+\.\d+)( \((?P<os>[^\)]+)\)))?)</center>").unwrap();

        regexes.insert("openssh-banner", openssh_regex);
        regexes.insert("http-header", header_regex);
        regexes.insert("http-body-apache", body_apache_regex);
        regexes.insert("http-body-nginx", body_nginx_regex);
        OSChecker { regexes: regexes }
    }

    /// Check for the technology in HTTP headers.
    fn check_http_headers(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running OSChecker::check_http_headers() on {}",
            url_response.url
        );
        let headers_to_check =
            url_response.get_headers(&vec!["Server".to_string(), "X-powered-by".to_string()]);

        // Check in the headers to check that were present in this UrlResponse
        for (header_name, header_value) in headers_to_check {
            trace!("Checking header: {} / {}", header_name, header_value);
            let caps_result = self
                .regexes
                .get("http-header")
                .expect("Regex \"http-header\" not found.")
                .captures(&header_value);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex OS/http-header matches");
                let caps = caps_result.unwrap();
                let os_name = caps["os"].to_string();
                let software = caps["software"].to_string();
                let software_version = caps["version"].to_string();
                let os_version = self.get_os_version(&os_name, &software, &software_version);
                let mut version_text = "".to_string();
                if os_version.is_some() {
                    version_text = format!(" {}", os_version.as_ref().unwrap());
                }
                let evidence = &header_value;
                let evidence_text = format!(
                        "The operating system {}{} has been identified using the HTTP header \"{}: {}\" returned at the following URL: {}",
                        os_name,
                        version_text,
                        header_name,
                        evidence,
                        url_response.url,
                    );
                return Some(Finding::new(
                    &os_name,
                    os_version,
                    evidence,
                    &evidence_text,
                    Some(&url_response.url),
                ));
            }
        }
        None
    }

    /// Check for the technology in the body.
    fn check_http_body(&self, url_response: &UrlResponse) -> Option<Finding> {
        trace!(
            "Running OSChecker::check_http_body() on {}",
            url_response.url
        );
        let caps_result = self
            .regexes
            .get("http-body-apache")
            .expect("Regex \"http-body-apache\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex OS/http-body-apache matches");
            let caps = caps_result.unwrap();
            let evidence = caps["wholematch"].to_string();
            let os_name = caps["os"].to_string();
            let software_version = caps["version"].to_string();
            let os_version = self.get_os_version(&os_name, "apache", &software_version);
            let mut version_text = "".to_string();
            if os_version.is_some() {
                version_text = format!(" {}", os_version.as_ref().unwrap());
            }

            let evidence_text = format!(
                    "The operating system {}{} has been identified by looking at the web server's signature \"{}\" at this page: {}",
                    os_name,
                    version_text,
                    evidence,
                    url_response.url
                );

            return Some(Finding::new(
                &os_name,
                os_version,
                &evidence,
                &evidence_text,
                Some(&url_response.url),
            ));
        }

        let caps_result = self
            .regexes
            .get("http-body-nginx")
            .expect("Regex \"http-body-nginx\" not found.")
            .captures(&url_response.body);

        // The regex matches
        if caps_result.is_some() {
            info!("Regex OS/http-body-nginx matches");
            let caps = caps_result.unwrap();
            let evidence = caps["wholematch"].to_string();
            let os_name = caps["os"].to_string();
            let software_version = caps["version"].to_string();
            let os_version = self.get_os_version(&os_name, "nginx", &software_version);
            let mut version_text = "".to_string();
            if os_version.is_some() {
                version_text = format!(" {}", os_version.as_ref().unwrap());
            }

            let evidence_text = format!(
                    "The operating system {}{} has been identified by looking at the web server's signature \"{}\" at this page: {}",
                    os_name,
                    version_text,
                    evidence,
                    url_response.url
                );

            return Some(Finding::new(
                &os_name,
                os_version,
                &evidence,
                &evidence_text,
                Some(&url_response.url),
            ));
        }
        None
    }

    /// Get the OS version according to the OS name, the software name and version.
    /// Example: Ubuntu 18.04 comes with Apache httpd 2.4.29
    ///
    /// TODO: handle backports to avoid false positive
    fn get_os_version(
        &self,
        os_name: &str,
        software_name: &str,
        software_version: &str,
    ) -> Option<&str> {
        trace!("Running OSChecker::get_os_version");
        let os = os_name.to_lowercase();
        let software = software_name.to_lowercase();
        let version = software_version.to_lowercase();

        debug!("Trying to guess OS version with the following values: OS name = {}, Software = {}, Software version = {}", os, software, version);

        // List the known versions of software
        let mut versions: HashMap<(&str, &str, &str), &str> = HashMap::new();
        // Ubuntu / Apache httpd
        versions.insert(("ubuntu", "apache", "2.4.29"), "18.04");
        versions.insert(("ubuntu", "apache", "2.4.41"), "20.04");
        versions.insert(("ubuntu", "apache", "2.4.52"), "22.04");
        versions.insert(("ubuntu", "apache", "2.4.54"), "22.10");
        versions.insert(("ubuntu", "apache", "2.4.55"), "23.04");

        // Ubuntu / Nginx
        versions.insert(("ubuntu", "nginx", "1.14.0"), "18.04");
        versions.insert(("ubuntu", "nginx", "1.18.0"), "20.04|22.04");
        versions.insert(("ubuntu", "nginx", "1.22.0"), "22.10|23.04");

        // Ubuntu / OpenSSH
        versions.insert(("ubuntu", "openssh", "7.6"), "18.04");
        versions.insert(("ubuntu", "openssh", "8.2"), "20.04");
        versions.insert(("ubuntu", "openssh", "8.9"), "22.04");
        versions.insert(("ubuntu", "openssh", "9.0"), "22.10|23.04");

        // Debian / Apache httpd
        versions.insert(("debian", "apache", "2.4.25"), "9");
        versions.insert(("debian", "apache", "2.4.38"), "10");
        versions.insert(("debian", "apache", "2.4.54"), "11");
        versions.insert(("debian", "apache", "2.4.57"), "12");

        // Debian / Nginx
        versions.insert(("debian", "nginx", "1.14.2"), "10");
        versions.insert(("debian", "nginx", "1.18.0"), "11");
        versions.insert(("debian", "nginx", "1.22.1"), "12");

        // Debian / OpenSSH
        versions.insert(("debian", "openssh", "7.9"), "10");
        versions.insert(("debian", "openssh", "8.4"), "11");
        versions.insert(("debian", "openssh", "9.2"), "12");

        // Oracle / OpenSSL
        versions.insert(("oracle", "openssl", "3.0.1"), "9.1");

        versions.get(&(&os, &software, &version)).copied()
    }
}

impl<'a> TcpChecker for OSChecker<'a> {
    /// Check what OS is running on the asset.
    /// It looks for the OpenSSH banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        trace!("Running OSChecker::check_tcp()");
        // For each item, check if it's an OpenSSH banner
        for item in data {
            trace!("Checking item: {}", item);
            let caps_result = self
                .regexes
                .get("openssh-banner")
                .expect("Regex \"openssh-banner\" not found.")
                .captures(item);
            // The regex matches
            if caps_result.is_some() {
                info!("Regex OS/openssh-banner matches");
                let caps = caps_result.unwrap();
                let os_name = caps["os"].to_string();
                let software_version = caps["version"].to_string();
                let os_version = self.get_os_version(&os_name, "openssh", &software_version);
                let mut version_text = "".to_string();
                if os_version.is_some() {
                    version_text = format!(" {}", os_version.as_ref().unwrap());
                }

                let os_evidence_text = format!(
                        "The operating system {}{} has been identified using the banner presented by OpenSSH.",
                        os_name,
                        version_text,
                    );
                return Some(Finding::new(
                    &os_name,
                    os_version,
                    item,
                    &os_evidence_text,
                    None,
                ));
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
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding> {
        trace!("Running OSChecker::check_http()");
        for url_response in data {
            // JavaScript files could be hosted on a different server
            // Don't check the JavaScript files to avoid false positive,
            // Check only the "main" requests.
            if url_response.request_type != UrlRequestType::Default {
                continue;
            }
            // Check in HTTP headers first
            let header_finding = self.check_http_headers(url_response);
            if header_finding.is_some() {
                return header_finding;
            }
            // Check in response body then
            let body_finding = self.check_http_body(url_response);
            if body_finding.is_some() {
                return body_finding;
            }
        }
        None
    }

    /// This checker supports the OS
    fn get_technology(&self) -> Technology {
        Technology::OS
    }
}
