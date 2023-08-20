//! Writing Findings
//!
//! After checkers finish their work, it's up to a writer to handle the
//! [`Finding`]s. It provides a common interface, allowing to work on the
//! findings without affecting the execution of the application.

pub mod csv;
pub mod textstdout;

use crate::models::Finding;

/// A trait to have a common interface between writers.
/// A writer has the responsibility to write the [`Finding`]s in a way,
/// be it on standard output, in a file, or to an API.
pub trait Writer {
    /// Create a new writer
    /// Due to the different kind of readers (TCP/UDP, HTTP), different options
    /// are allowed as parameter. Only set the right one(s).
    /// In an HTTP scan, set the `url` to Some(...).
    /// In a TCP or UDP scan, set the `ip_hostname` and `port` to Some(...).
    fn new(ip_hostname: Option<String>, port: Option<u16>, url: Option<String>) -> Self
    where
        Self: Sized;

    /// Write the findings
    /// What is done with the [`Finding`]s is totally up to the writer.
    /// They could be written to stdout, to a file, sent to an API, etc.
    fn write(&self, findings: Vec<Finding>);
}
