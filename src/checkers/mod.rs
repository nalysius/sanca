//! This module declares all the checkers.
//! A checker is a struct that checks an input (banner, HTTP headers, etc)
//! to against a technology.

pub mod dovecot;
pub mod exim;
pub mod handlebars;
pub mod httpd;
pub mod jquery;
pub mod mariadb;
pub mod mysql;
pub mod nginx;
pub mod openssh;
pub mod openssl;
pub mod os;
pub mod php;
pub mod proftpd;
pub mod pureftpd;

use crate::models::{Finding, Technology, UrlResponse};

/// A common interface between all TCP checkers
pub trait TcpChecker {
    /// Checks data to determine if a given technology matches.
    /// data will usually contain only one string (the banner), but
    /// some technologies could provide more information.
    fn check_tcp(&self, data: &[String]) -> Option<Finding>;

    /// Get the technology supported by the checker.
    fn get_technology(&self) -> Technology;
}

/// A common interface between all HTTP checkers
pub trait HttpChecker {
    /// Checks data to determine if a given technology matches.
    /// data will contain information about HTTP request & response.
    fn check_http(&self, data: &[UrlResponse]) -> Option<Finding>;

    /// Get the technology supported by the checker.
    fn get_technology(&self) -> Technology;
}
