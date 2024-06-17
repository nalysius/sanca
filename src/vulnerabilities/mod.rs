//! The vulnerabilities module contains what's needed to associate
//! vulnerabilities to findings.
//!
//! It is composed of two parts, fetchers and cache managers.
//! A fetcher is there to fetch the vulnerabilities from a source (e.g. NVD, Mitre).
//! A cache manager stores the vulnerabilities fetched by the fetcher
//! (e.g. in files or database)

pub mod cache_managers;
pub mod fetchers;

use clap::{builder::PossibleValue, ValueEnum};

/// This enum represents the source of the vulnerabilities.
#[derive(Clone, Debug)]
pub enum VulnSource {
    /// The vulnerabilities are downloaded from the NVD.
    NVD,
}

impl ValueEnum for VulnSource {
    /// Lists the variants available for clap
    fn value_variants<'a>() -> &'a [Self] {
        &[VulnSource::NVD]
    }

    /// Map each value to a possible value in clap
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            VulnSource::NVD => Some(PossibleValue::new("nvd")),
        }
    }
}

/// This enum represents the type of cache that can be used.
#[derive(Clone, Debug)]
pub enum CacheType {
    /// The cache will store the vulnerabilities in files.
    Files,
}

impl ValueEnum for CacheType {
    /// Lists the variants available for clap
    fn value_variants<'a>() -> &'a [Self] {
        &[CacheType::Files]
    }

    /// Map each value to a possible value in clap
    fn to_possible_value(&self) -> Option<PossibleValue> {
        match &self {
            CacheType::Files => Some(PossibleValue::new("files")),
        }
    }
}
