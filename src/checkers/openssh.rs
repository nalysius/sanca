//! The OpenSSH checker.
//! This module contains the checker used to determine if OpenSSH is
//! used by the asset.
//! https://www.openssh.com

use std::collections::HashMap;

use super::{Checker, TcpChecker};
use crate::models::{technology::Technology, Finding};
use log::{info, trace};
use regex::Regex;

/// The OpenSSH checker
pub struct OpenSSHChecker<'a> {
    /// The regexes and their parameters used to recognize the technology
    /// The left-side usize represent the number of chars to keep in the
    /// evidence, from the left, if the regex matches. The right-side is
    /// similar but it's about the number of chars to keep from the right.
    regexes: HashMap<&'a str, (Regex, usize, usize)>,
}

impl<'a> Checker for OpenSSHChecker<'a> {}

impl<'a> OpenSSHChecker<'a> {
    /// Creates a new OpenSSHChecker.
    /// By doing so, the regex will is compiled once and the checker can be
    /// reused.
    pub fn new() -> Self {
        let mut regexes = HashMap::new();
        // Example: SSH-2.0-OpenSSH_6.7p1 Debian-5
        // SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u2
        // Note: the -5 is actually ignored. Could be handled later.
        // TODO: get the package name & version when possible
        let regex = Regex::new(r"^(?P<wholematch>SSH-(?P<sshversion>\d+\.\d+)-OpenSSH_(for_Windows_)?(?P<version1>\d+\.\d+([a-z]\d+)?)( [a-zA-Z0-9+~\.-]+)?)").unwrap();
        regexes.insert("openssh-banner", (regex, 20, 20));
        OpenSSHChecker { regexes: regexes }
    }
}

impl<'a> TcpChecker for OpenSSHChecker<'a> {
    /// Check if the asset is running OpenSSH.
    /// It looks for the OpenSSH banner.
    fn check_tcp(&self, data: &[String]) -> Option<Finding> {
        trace!("Running OpenSSHChecker::check_tcp()");
        // For each item, check if it's an OpenSSH banner
        for item in data {
            trace!("Checking item: {}", item);
            let banner_regex_params = self
                .regexes
                .get("openssh-banner")
                .expect("Regex OpenSSH/openssh-banner not found");
            let (regex, keep_left, keep_right) = banner_regex_params;
            let caps_result = regex.captures(&item);

            // The regex matches
            if caps_result.is_some() {
                info!("Regex OpenSSH/openssh-banner matches");
                let caps = caps_result.unwrap();
                let _ssh_version = caps.name("sshversion");
                return Some(self.extract_finding_from_captures(
		    caps,
		    None,
		    keep_left.to_owned(),
		    keep_right.to_owned(),
		    "OpenSSH",
		    "$techno_name$$techno_version$ has been identified because we found \"$evidence$\" in its banner",
		));
            }
        }
        return None;
    }

    /// This checker supports OpenSSH
    fn get_technology(&self) -> Technology {
        Technology::OpenSSH
    }
}
