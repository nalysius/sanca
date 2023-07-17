//! This module declares the writers.
//! A writer is a way to present the findings.
//! Writers could be text / stdout, csv file and so on.

pub mod textstdout;

use crate::models::Finding;

/// A trait to have a common interface between writers.
pub trait Writer {
    /// Write the findings
    fn write(&self, findings: Vec<Finding>);
}
