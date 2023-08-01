//! This module declares the writers.
//! A writer is a way to present the findings.
//! Writers could be text / stdout, csv file and so on.

pub mod csv;
pub mod textstdout;

use crate::models::Finding;

/// A trait to have a common interface between writers.
pub trait Writer {
    /// Create a new writer
    fn new(ip_hostname: Option<String>, port: Option<u16>, url: Option<String>) -> Self
    where
        Self: Sized;
    /// Write the findings
    fn write(&self, findings: Vec<Finding>);
}
