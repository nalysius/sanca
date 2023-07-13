//! This module declares all the checkers.
//! A checker is a struct that checks an input (banner, HTTP headers, etc)
//! to against a technology.

pub mod exim;
pub mod mariadb;
pub mod mysql;
pub mod openssh;
pub mod proftpd;

use crate::models::Finding;

/// A common interface between all TCP checkers
pub trait TcpChecker {
    /// Checks data to determine if a given technology matches.
    /// data will usually contain only one string (the banner), but
    /// some technologies could provide more information
    fn check(&self, data: &[String]) -> Vec<Finding>;
}