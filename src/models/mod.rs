//! In this module are declared the entities manipulated by this program

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

/// Represent a target to scan
pub struct Target {
    /// The IPv4 address or hostname of the target
    /// A target can be scanned either by its IP address or its hostname
    pub ip_hostname: String,
    /// The list of ports to scan on the target
    pub ports_to_scan: Vec<Port>,
}

