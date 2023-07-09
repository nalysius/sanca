//! In this module are declared the entities manipulated by this program

use self::technologies::Technology;

pub mod technologies;

/// Represents which protocol is used between TCP and UDP
#[derive(Clone, PartialEq)]
pub enum TransportLayerProtocol {
    /// Protocol TCP
    Tcp,
    /// Protocol UDP
    Udp,
}

/// Represents a port
#[derive(Clone, PartialEq)]
pub struct Port {
    /// The number of the port
    pub number: u16,
    /// Which protocol to use to connect to the port
    pub layer4_protocol: TransportLayerProtocol,
}

impl Port {
    /// Creates a new TCP port
    pub fn new_tcp(number: u16) -> Self {
        Port {
            number: number,
            layer4_protocol: TransportLayerProtocol::Tcp,
        }
    }

    /// Create a new UDP port
    pub fn new_udp(number: u16) -> Self {
        Port {
            number,
            layer4_protocol: TransportLayerProtocol::Udp,
        }
    }
}

/// Represents an asset to scan
pub struct Asset {
    /// The IPv4 address or hostname of the asset
    /// A target can be scanned either by its IP address or its hostname
    pub ip_hostname: String,
    /// The list of ports to scan on the asset
    pub ports_to_scan: Vec<Port>,
}

/// Represents a finding of a technology running on an asset
pub struct Finding {
    /// The technology found
    pub technology: Technology,
    /// The version of the technology
    pub version: String,
}