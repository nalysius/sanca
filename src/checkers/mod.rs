//! A checker has the role of checking data to confirm whether a given
//! technology is used on the remote host.
//!
//! Checkers are the core of Sanca, each checker checks for one
//! technology using regular expressions, fingerprinting or other
//! techniques.
//!
//! Checkers are grouped by scan type. Actually there are three types of
//! checkers: TCP, UDP and HTTP.
//! A checker is relevant only for a given scan type, for example jQuery
//! cannot be identified from a TCP banner, so it's not needed to check
//! it. A checker can have several types (see [`os::OSChecker`]), but it
//! has to have at least one.
//!

pub mod angular;
pub mod angularjs;
pub mod bootstrap;
pub mod ckeditor;
pub mod dovecot;
pub mod exim;
pub mod gsap;
pub mod handlebars;
pub mod highcharts;
pub mod httpd;
pub mod jira;
pub mod jquery;
pub mod jqueryui;
pub mod lodash;
pub mod mariadb;
pub mod melis;
pub mod mysql;
pub mod nginx;
pub mod openssh;
pub mod openssl;
pub mod os;
pub mod phonesystem_3cx;
pub mod php;
pub mod phpmyadmin;
pub mod plesk;
pub mod prestashop;
pub mod proftpd;
pub mod pureftpd;
pub mod reactjs;
pub mod squirrel_mail;
pub mod symfony;
pub mod tinymce;
pub mod tomcat;
pub mod twisted;
pub mod twistedweb;
pub mod typo3;
pub mod wordpress;
pub mod wp_plugins;
pub mod wp_themes;

use crate::models::{reqres::UrlResponse, technology::Technology, Finding};
use log::trace;
use regex::Captures;

/// A common interface between all TCP checkers
pub trait TcpChecker: Checker {
    /// Checks data to determine if a given technology matches.
    /// data will usually contain only one string (the banner), but
    /// some technologies could provide more information.
    fn check_tcp(&self, data: &[String]) -> Option<Finding>;

    /// Get the technology supported by the checker.
    fn get_technology(&self) -> Technology;
}

/// A common interface between all HTTP checkers
pub trait HttpChecker: Checker {
    /// Checks data to determine if a given technology matches.
    /// data will contain information about HTTP request & response.
    fn check_http(&self, data: &[UrlResponse]) -> Vec<Finding>;

    /// Get the technology supported by the checker.
    fn get_technology(&self) -> Technology;
}

// A common interface between all checkers
pub trait Checker {
    /// Extract a finding from captures
    /// It is a common method used by most JavaScript checkers, so
    /// it's easier to defined it here.
    ///
    /// Actually it searches for the regex groups "wholematch" and "version".
    /// "wholematch" MUST be present. It is used as the evidence, and is
    /// truncated if needed.
    ///
    /// If the evidence (wholematch) is longer than evidence_first_chars + evidence_last_chars,
    /// it will be cut in the middle. So, only the given number of chars will
    /// remains at the beginning, and the other given number for the end.
    fn extract_finding_from_captures(
        &self,
        captures: Captures,
        url_response: Option<&UrlResponse>,
        evidence_first_chars: usize,
        evidence_last_chars: usize,
        technology_name: &str,
        evidence_text_templace: &str,
    ) -> Finding {
        trace!("Running HttpChecker::extract_finding_from_captures()");
        let mut evidence = captures["wholematch"].to_string();
        trace!("Evidence: {}", evidence);
        let evidence_length = evidence.len();
        if evidence_length > evidence_first_chars + evidence_last_chars {
            trace!("Evidence is too long, truncate it");
            let evidencep1 = evidence[0..evidence_first_chars].to_string();
            let evidencep2 = evidence[evidence_length - evidence_last_chars..].to_string();
            evidence = format!("{}[...]{}", evidencep1, evidencep2);
            trace!("New evidence: {}", evidence);
        }

        let mut version = None;
        let mut version_text = String::new();
        // Some technologies (e.g. TinyMCE) split their version
        // in several parts. In most cases, only the matching group "version1"
        // will be used, but in some occasions it will be needed to use also
        // "version2", "version3", etc.
        for version_part in 1..5 {
            let version_part_match = captures.name(&format!("version{}", version_part));
            if version_part_match.is_some() {
                let version_part_text = version_part_match.unwrap().as_str();
                // Version parts are separated by a dot
                if !version_text.is_empty() {
                    version_text.push('.');
                }
                version_text.push_str(version_part_text);
            }
        }

        // Add a space in the version, so in the evidence text we
        // avoid a double space if the version is not found
        if !version_text.is_empty() {
            version = Some(version_text.clone());
            version_text = format!(" {}", version_text);
            trace!("Version: {}", version_text);
        }

        let mut url = "";
        let mut url_option = None;
        if url_response.is_some() {
            url = url_response.unwrap().url.as_str();
            url_option = Some(url);
        }

        let evidence_text = evidence_text_templace
            .replace("$techno_name$", technology_name)
            .replace("$techno_version$", &version_text)
            .replace("$evidence$", &evidence)
            .replace("$url_of_finding$", &url);

        trace!("Evidence text: {}", evidence_text);

        return Finding::new(
            technology_name,
            version.as_deref(),
            &evidence,
            &evidence_text,
            url_option,
        );
    }
}

/// Checks the fields of a Finding to ensure they are properly set.
///
/// Note: this method is not a test, it's a utility available to all
/// the checkers.
///
/// finding_option: the optional Finding to call assertions on.
/// evidence: a string to find in the evidence
/// technology: the technology name
/// version: the optional version of the technology
/// url: the optional URL of the finding.
///
/// # Example
///
/// ```rust
/// let finding = Finding::new(
///     "WordPress",
///     Some("6.1.2"),
///     "<meta name='generator' content='WordPress 6.1.2'/>",
///     "WordPress 6.1.2 has been identified because we found 'content='WordPress 6.1.2'/>' at 'https://example.com/blog/index.php'"
///     Some("https://example.com/blog/index.php")
///     );
///
/// check_finding_fields(
///     Some(finding),
///     "content='WordPress 6.1.2'",
///     "WordPress",
///     Some("6.1.2"),
///     Some("https://example.com/blog/index.php")
/// );
/// ```
#[cfg(test)]
fn check_finding_fields(
    finding: &Finding,
    evidence: &str,
    technology: &str,
    version: Option<&str>,
    url: Option<&str>,
) {
    let evidence_text = &finding.evidence_text;

    if url.is_some() {
        assert!(
            finding.url_of_finding.is_some(),
            "Assertion 'finding.url_of_finding.is_some()' failed. Expected URL: {}",
            url.unwrap()
        );
        assert_eq!(
            finding.url_of_finding.as_ref().unwrap(),
            url.unwrap(),
            "Assertion 'finding.url_of_finding == url' failed. Finding's URL: {}, url: {}",
            url.as_ref().unwrap(),
            finding.url_of_finding.as_ref().unwrap()
        );
        assert!(
            evidence_text.contains(url.unwrap()),
            "Assertion 'finding.evidence_text.contains(url)' failed. Finding's evidence text: {}, url: {}",
            evidence_text,
            url.unwrap()
        );
    }

    assert!(
        finding.evidence.contains(evidence),
        "Assertion 'finding.evidence.contains(evidence)' failed. Finding's evidence: {}, evidence: {}",
        finding.evidence,
        evidence
    );
    assert_eq!(
        finding.technology,
        technology,
        "Assertion 'finding.technology == technology' failed. Finding's technology: {}, technology: {}",
        finding.technology,
        technology
    );
    assert!(
        evidence_text.contains(technology),
        "Assertion 'finding.evidence_text.contains(technology)' failed. Finding's evidence text: {}, technology: {}",
        evidence_text,
        technology
    );
    assert!(
        evidence_text.contains(evidence),
        "Assertion 'finding.evidence_text.contains(evidence)' failed. Finding's evidence text: {}, evidence: {}",
        evidence_text,
        evidence
    );

    if version.is_some() {
        assert!(
            finding.version.is_some(),
            "Assertion 'finding.version.is_some()' failed. Expected version: {}",
            version.unwrap()
        );
        assert_eq!(
            finding.version.as_ref().unwrap(),
            version.unwrap(),
            "Assertion 'finding.version == version' failed. Finding's version: {}, version: {}",
            finding.version.as_ref().unwrap(),
            version.unwrap()
        );
        assert!(
            evidence_text.contains(version.unwrap()),
            "Assertion 'finding.evidence_text.contains(version)' failed. Finding's evidence text: {}, version:{}",
            evidence_text,
            version.unwrap()
        );
    }
}
