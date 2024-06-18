use crate::models::{Finding, CVE as CVEModel};
use crate::vulnerabilities::cache_managers::CacheManager;
use crate::vulnerabilities::fetchers::VulnFetcher;
/// This module implements a vulnerability fetcher which downloads
/// the CVEs from the NVD.
/// https://nvd.nist.gov/developers/vulnerabilities
use log::{debug, error, trace};
use serde::Deserialize;

/// This structs represents the NVD vulnerabilities fetcher.
pub struct NVDFetcher {
    /// An optional cache manager to reduce API calls.
    cache: Option<Box<dyn CacheManager>>,
}

impl NVDFetcher {
    /// Fetches the vulnerabilities for a finding
    pub fn fetch_vulns(&self, finding: &mut Finding) {
        trace!("Running NVDFetcher::fetch_vulns()");
        let (part, vendor, product) = finding.technology.get_cpe_part_vendor_product();
        if vendor.is_empty() || product.is_empty() || finding.version.is_none() {
            debug!("Vendor, product of version is empty, technology is ignored.");
            return;
        }
        // Example: https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected&cpeName=cpe:2.3:a:jquery:jquery:1.8.3
        let nvd_url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected&cpeName=cpe:2.3:{}:{}:{}:{}", part, vendor, product, finding.version.as_ref().unwrap());
        let response_opt = reqwest::blocking::get(nvd_url);
        let response = if let Err(e) = response_opt {
            error!("Error while communicating with NVD. {:?}", e);
            return;
        } else {
            response_opt.unwrap()
        };

        if !response.status().is_success() {
            error!("Invalid HTTP response code: {}", response.status());
            return;
        }

        let nvd_response: APIResponse = if let Ok(n) = response.json() {
            n
        } else {
            error!("Invalid JSON returned by NVD API.");
            return;
        };

        for vulnerability in nvd_response.vulnerabilities {
            let cve: CVEModel = vulnerability.into();
            if cve.base_score > 0.0 && !finding.vulnerabilities.contains(&cve) {
                finding.vulnerabilities.push(cve);
            }
        }

        if let Some(c) = self.cache.as_ref() {
            c.store(
                finding.vulnerabilities.clone(),
                finding.technology.clone(),
                finding.version.as_ref().unwrap(),
            );
        }
    }
}

impl VulnFetcher for NVDFetcher {
    /// Creates a new NVDFetcher.
    fn new(cache: Option<Box<dyn CacheManager>>) -> Self {
        Self { cache }
    }

    /// Complete the findings with vulnerabilities coming from the NVD.
    fn complete_findings(&self, findings: &mut Vec<Finding>) {
        for finding in findings {
            let mut cache_found = false;
            if self.cache.is_some() {
                cache_found = self.cache.as_ref().unwrap().complete_finding(finding);
            }
            if !cache_found {
                self.fetch_vulns(finding);
            }
        }
    }
}

/// Represents the main JSON object returned by the NVD CVE API.
#[derive(Debug, Deserialize)]
pub struct APIResponse {
    /// The number of results by page.
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: u32,
    /// The start index.
    #[serde(rename = "startIndex")]
    pub start_index: u32,
    /// The format.
    pub format: String,
    /// The version.
    pub version: String,
    /// The timestamp.
    pub timestamp: String,
    /// The list of vulnerabilities.
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Represents a vulnerability returned as part of the APIResponse.
#[derive(Debug, Deserialize)]
pub struct Vulnerability {
    /// The CVE.
    pub cve: CVE,
}

/// Represents a CVE as returned as part of the Vulnerability.
#[derive(Debug, Deserialize)]
pub struct CVE {
    /// The CVE identifier.
    /// Example: CVE-2012-6708
    pub id: String,
    /// The source identifier.
    /// Example: cve@mitre.org
    #[serde(rename = "sourceIdentifier")]
    pub source_identifier: String,
    /// When the CVE was published.
    /// Example: 2018-01-18T23:29:00.213
    pub published: String,
    /// When the CVE was modified.
    /// Example: 2023-11-07T02:13:33.290
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    /// The status of the vulnerability.
    /// Example: Modified
    #[serde(rename = "vulnStatus")]
    pub vuln_status: String,
    /// The descriptions of the CVE.
    /// Example: [{"lang": "en", "value": "jQuery before 1.9.0 is vulnerable to [...]"}]
    pub descriptions: Vec<CVEDescription>,
    /// The metrics related to the CVE.
    pub metrics: CVEMetrics,
}

/// Represents a description as part of a CVE.
#[derive(Debug, Deserialize)]
pub struct CVEDescription {
    /// The language of the description.
    /// Example: en
    pub lang: String,
    /// The content of the description.
    /// Example: jQuery before 1.9.0 is vulnerable to [...]
    pub value: String,
}

/// Represents the metrics as part of a CVE.
#[derive(Debug, Deserialize)]
pub struct CVEMetrics {
    /// The data about CVSS 3.1
    #[serde(rename = "cvssMetricV31")]
    pub cvss_metric_v31: Option<Vec<CVSSMetric<CVSS3Data>>>,
    /// The data about CVSS 3.0
    #[serde(rename = "cvssMetricV30")]
    pub cvss_metric_v30: Option<Vec<CVSSMetric<CVSS3Data>>>,
    /// The data about CVSS 2
    #[serde(rename = "cvssMetricV2")]
    pub cvss_metric_v2: Option<Vec<CVSSMetric<CVSS2Data>>>,
}

/// Represents a CVSS metric.
#[derive(Debug, Deserialize)]
pub struct CVSSMetric<T: CVSSData> {
    /// The source of the metric.
    /// Example: nvd@nist.gov
    pub source: String,
    /// The type of metric.
    /// Example: Primary
    #[serde(rename = "type")]
    pub metric_type: String,
    /// The CVSS data
    #[serde(rename = "cvssData")]
    pub cvss_data: T,
    /// The exploitability score.
    #[serde(rename = "exploitabilityScore")]
    pub exploitability_score: f32,
    /// The impact score.
    #[serde(rename = "impactScore")]
    pub impact_score: f32,
}

/// An empty trait that will be implemented by all CVSSxxData structures
pub trait CVSSData {}

/// Represents the CVSS 3 data.
#[derive(Debug, Deserialize)]
pub struct CVSS3Data {
    /// The version of CVSS.
    /// Example: 3.1
    pub version: String,
    /// The vector string.
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    /// Attack vector.
    #[serde(rename = "attackVector")]
    pub attack_vector: String,
    /// Attack complexity.
    #[serde(rename = "attackComplexity")]
    pub attack_complexity: String,
    /// Privileges required.
    #[serde(rename = "privilegesRequired")]
    pub privileges_required: String,
    /// User interaction.
    #[serde(rename = "userInteraction")]
    pub user_intectaction: String,
    /// The scope.
    pub scope: String,
    /// Confidentiality impact
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: String,
    /// Integrity impact.
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: String,
    /// Availability impact.
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: String,
    /// The base score.
    #[serde(rename = "baseScore")]
    pub base_score: f32,
    /// The base severity.
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
}

impl CVSSData for CVSS3Data {}

/// Represents the CVSS 2 data.
#[derive(Debug, Deserialize)]
pub struct CVSS2Data {
    /// The version of CVSS.
    /// Example: 2.0
    pub version: String,
    /// The vector string.
    #[serde(rename = "vectorString")]
    pub vector_string: String,
    /// Access vector.
    #[serde(rename = "accessVector")]
    pub access_vector: String,
    /// Access complexity.
    #[serde(rename = "accessComplexity")]
    pub access_complexity: String,
    /// Authentication.
    pub authentication: String,
    /// Confidentiality impact
    #[serde(rename = "confidentialityImpact")]
    pub confidentiality_impact: String,
    /// Integrity impact.
    #[serde(rename = "integrityImpact")]
    pub integrity_impact: String,
    /// Availability impact.
    #[serde(rename = "availabilityImpact")]
    pub availability_impact: String,
    /// The base score.
    #[serde(rename = "baseScore")]
    pub base_score: f32,
}

impl CVSSData for CVSS2Data {}
