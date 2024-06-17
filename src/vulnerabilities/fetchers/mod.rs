/// The module fetchers defines the vulnerabilities fetchers.
pub mod nvd;

use crate::models::Finding;
use crate::vulnerabilities::cache_managers::CacheManager;

/// A common interface between all vulnerabilities fetchers.
pub trait VulnFetcher {
    /// Creates a new instance of the fetcher.
    fn new(cache: Option<Box<dyn CacheManager>>) -> Self;

    /// Complete the findings with the vulnerabilities.
    fn complete_findings(&self, findings: &mut Vec<Finding>);
}
