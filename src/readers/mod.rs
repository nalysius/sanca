//! A reader has the responsibility to fetch data from a remove host.
//!
//! Main readers are TCP, UDP and HTTP. Their objective is to make easier
//! fetching data, to focus on the identification of the technology.

pub mod http;
pub mod tcp;
