/// This module contains the FileCacheManager struct.
use crate::models::{technology::Technology, Finding, CVE};
use crate::vulnerabilities::cache_managers::CacheManager;
use log::{error, trace};
use std::env;
use std::fs::{create_dir_all, File};
use std::io::prelude::*;
use std::path::{Path, PathBuf};

/// Represents a cache manager which stores the data in files.
pub struct FileCacheManager {}

impl FileCacheManager {
    pub fn new() -> Self {
        Self {}
    }
}

impl CacheManager for FileCacheManager {
    /// Complete the finding with vulnerabilities stored in files.
    /// Returns true if the technology & version in the finding were
    /// stored in cache, false otherwise.
    fn complete_finding(&self, finding: &mut Finding) -> bool {
        if finding.version.is_none() {
            return false;
        }
        if let Some(cves) = self.read(
            finding.technology.clone(),
            &finding.version.as_ref().unwrap(),
        ) {
            finding.vulnerabilities = cves;
            return true;
        } else {
            return false;
        }
    }

    /// Read the CVEs associated with a Technology & version in cache.
    fn read(&self, technology: Technology, version: &str) -> Option<Vec<CVE>> {
        trace!("Running FileCacheManager::read");
        let root_dir = if let Ok(mut p) = env::current_exe() {
            p.pop();
            p.join("cves")
        } else {
            // By default, a "cves" directory is created in the current working directory
            PathBuf::new().join("cves")
        };

        let (_part, vendor, product) = technology.get_cpe_part_vendor_product();
        let dirname = Path::new(&root_dir).join(vendor).join(product);
        if !dirname.exists() {
            return None;
        }

        let filename = dirname.join(&format!("{}.json", version));
        if !filename.exists() {
            return None;
        }

        let mut file = if let Ok(f) = File::open(filename.clone()) {
            f
        } else {
            error!(
                "Unable to open the JSON file {}",
                filename.to_string_lossy()
            );
            return None;
        };

        let mut json = String::new();
        if file.read_to_string(&mut json).is_err() {
            error!(
                "Unable to read the JSON file {}",
                filename.to_string_lossy()
            );
            return None;
        }

        let cves: Vec<CVE> = if let Ok(c) = serde_json::from_str(json.as_str()) {
            c
        } else {
            return None;
        };
        return Some(cves);
    }

    /// Stores the CVEs associated with a Technology & version in cache.
    ///
    /// The cache has the following structure:
    /// cves/
    ///   \__<cpe_vendor>/
    ///        \__<cpe_product>
    ///              \__<version>.json
    ///
    /// The JSON files contain an array of CVEs.
    fn store(&self, vulns: Vec<CVE>, technology: Technology, version: &str) {
        trace!("Running FileCacheManager::store");
        let root_dir = if let Ok(mut p) = env::current_exe() {
            p.pop();
            p.join("cves")
        } else {
            // By default, a "cves" directory will be created in the current working directory
            PathBuf::new().join("cves")
        };

        let vulns_json = if let Ok(j) = serde_json::value::to_value(vulns) {
            format!("{:#}", j)
        } else {
            error!("Error while serializing a CVE to a JSON string");
            return;
        };

        let (_part, vendor, product) = technology.get_cpe_part_vendor_product();
        let dirname = Path::new(&root_dir).join(vendor).join(product);
        if !dirname.exists() {
            let create_result = create_dir_all(&dirname);
            if create_result.is_err() {
                error!(
                    "Unable to create the directory {}",
                    dirname.to_string_lossy()
                );
                return;
            }
        }
        let filename = dirname.join(&format!("{}.json", version));
        if !filename.exists() {
            let mut file = if let Ok(f) = File::create(filename.clone()) {
                f
            } else {
                error!("Unable to create the file {}", filename.to_string_lossy());
                return;
            };

            if file.write_all(vulns_json.as_bytes()).is_err() {
                error!("Unable to write the file {}", filename.to_string_lossy());
            }
        }
    }
}
