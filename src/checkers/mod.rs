//! This module declares all the checkers.
//! A checker is a struct that checks an input (banner, HTTP headers, etc)
//! to against a technology.

use crate::models::Finding;

/// A common interface between all checkers
pub trait Checker {
    /// Checks data to determine if a given technology matches.
    /// data will usually contain only one string (the banner), but
    /// some technologies could provide information from different
    /// sources (HTTP headers & response for example).
    fn check(data: &[String]) -> Vec<Finding>;
}