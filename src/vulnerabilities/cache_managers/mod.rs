/// The module cache_managers defines the vulnerabilities cache managers.
pub mod files;

use crate::models::{technology::Technology, Finding, CVE};

/// A common interface between all cache managers.
pub trait CacheManager {
    /// Completes the finding with vulnerabilities stored in cache.
    /// Returns true if the technology & version in the finding were
    /// stored in cache, false otherwise.
    fn complete_finding(&self, finding: &mut Finding) -> bool;

    /// Read the CVEs associated with a Technology & version in cache.
    fn read(&self, technology: Technology, version: &str) -> Option<Vec<CVE>>;

    /// Stores the CVEs associated with a Technology & version in cache.
    fn store(&self, vulns: Vec<CVE>, technology: Technology, version: &str);
}
