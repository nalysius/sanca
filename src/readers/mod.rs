//! This module declares all readers.
//! A reader is used to fetch data over the network. Main readers
//! are TCP, UDP and HTTP. Their objective is to make easier
//! fetching data, to focus on the identification of the technology.

pub mod http;
pub mod tcp;
