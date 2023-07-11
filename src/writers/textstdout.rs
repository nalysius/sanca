//! This module declares the TextStdout writer.
//! It is the default writer, it presents the findings in a text
//! format and prints it on STDOUT.

use crate::models::Finding;
use super::Writer;

/// A writer to print the findings in the terminal.
pub struct TextStdout {

}

impl TextStdout {
    pub fn new() -> Self {
        TextStdout {
            
        }
    }
}

impl Writer for TextStdout {
    /// Prints the findings on STDOUT
    fn write(&self, findings: Vec<Finding>) {
        for finding in findings {
            let mut version = "unknown";
            if finding.version.is_some() {
                version = &finding.version.as_ref().unwrap();
            }
            println!("[{}/{}] {}", finding.technology, version, finding.evidence_text);
        }
    }
}