//! This module declares all the checkers.
//! A checker is a struct that checks an input (banner, HTTP headers, etc)
//! to against a technology.

pub mod openssh;

use crate::models::{Finding, ScanType};

/// A common interface between all checkers
pub trait Checker {
    /// Checks data to determine if a given technology matches.
    /// data will usually contain only one string (the banner), but
    /// some technologies could provide information from different
    /// sources (HTTP headers & response for example).
    fn check(&self, data: &[String]) -> Vec<Finding>;
    /// Gets the different types of scans for the current checker.
    /// As an example, an OpenSSH checker would be TCP, while an
    /// Apache httpd checker would be HTTP. A software running on
    /// TCP & UDP could use both scan types.
    fn get_scan_types() -> Vec<ScanType>;
}