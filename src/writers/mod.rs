//! Writing Findings
//!
//! After checkers finish their work, it's up to a writer to handle the
//! [`Finding`]s. It provides a common interface, allowing to work on the
//! findings without affecting the execution of the application.

pub mod csv;
pub mod json;
pub mod textstdout;

use crate::{application::Args, models::Finding};

/// A trait to have a common interface between writers.
/// A writer has the responsibility to write the [`Finding`]s in a way,
/// be it on standard output, in a file, or to an API.
pub trait Writer {
    /// Create a new writer
    /// Due to the different kind of readers (TCP/UDP, HTTP), the whole argv is given.
    /// Only set the right one(s).
    fn new(argv: &Args) -> Self
    where
        Self: Sized;

    /// Write the findings
    /// What is done with the [`Finding`]s is totally up to the writer.
    /// They could be written to stdout, to a file, sent to an API, etc.
    fn write(&self, findings: Vec<Finding>);
}
