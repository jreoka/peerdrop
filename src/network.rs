use if_addrs::get_if_addrs;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, mdns, noise, tcp, yamux, StreamProtocol, Swarm, SwarmBuilder};
use libp2p_stream as stream;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

#[derive(NetworkBehaviour)]
pub struct AppBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub stream: stream::Behaviour,
    pub identify: identify::Behaviour,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ticket {
    pub c: String,        // code
    pub a: Vec<String>,    // multiaddresses
}

impl Ticket {
    pub fn to_base58(&self) -> Result<String, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(format!("pd1_{}", bs58::encode(json).into_string()))
    }

    pub fn from_str(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("Code or ticket cannot be empty".into());
        }

        if let Some(payload) = trimmed.strip_prefix("pd1_") {
            let bytes = bs58::decode(payload)
                .into_vec()
                .map_err(|e| format!("Invalid base58 ticket: {}", e))?;
            let ticket: Ticket =
                serde_json::from_slice(&bytes).map_err(|e| format!("Invalid ticket JSON: {}", e))?;
            if ticket.c.trim().is_empty() {
                return Err("Ticket contains empty transfer code".into());
            }
            return Ok(ticket);
        }

        // Check if code@address format: "4821-cosmic-falcon@192.168.1.15:52341"
        if let Some((code, addr_part)) = trimmed.split_once('@') {
            let code = code.trim();
            if code.is_empty() {
                return Err("Code cannot be empty in code@address format".into());
            }
            let multiaddr = if addr_part.starts_with('/') {
                addr_part.to_string()
            } else if let Ok(socket_addr) = addr_part.parse::<std::net::SocketAddr>() {
                match socket_addr.ip() {
                    IpAddr::V4(ipv4) => format!("/ip4/{}/tcp/{}", ipv4, socket_addr.port()),
                    IpAddr::V6(ipv6) => format!("/ip6/{}/tcp/{}", ipv6, socket_addr.port()),
                }
            } else {
                return Err(format!("Invalid address part '{}'", addr_part));
            };
            return Ok(Ticket {
                c: code.to_string(),
                a: vec![multiaddr],
            });
        }

        // Pure code: no direct addresses, uses mDNS
        Ok(Ticket {
            c: trimmed.to_string(),
            a: Vec::new(),
        })
    }
}

pub struct P2pNode {
    pub swarm: Swarm<AppBehaviour>,
    pub stream_control: stream::Control,
    pub local_ips: Vec<IpAddr>,
}

pub fn create_p2p_node() -> Result<P2pNode, Box<dyn std::error::Error>> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                key.public().to_peer_id(),
            )?;
            let stream = stream::Behaviour::new();
            let identify = identify::Behaviour::new(identify::Config::new(
                "/peerdrop/1.0.0".into(),
                key.public(),
            ));
            Ok(AppBehaviour {
                mdns,
                stream,
                identify,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let stream_control = swarm.behaviour().stream.new_control();

    // Listen on TCP port 0 (OS allocates free port)
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Collect non-loopback local IPv4 addresses
    let mut local_ips = Vec::new();
    if let Ok(interfaces) = get_if_addrs() {
        for iface in interfaces {
            if !iface.is_loopback() && let IpAddr::V4(ipv4) = iface.ip() {
                local_ips.push(IpAddr::V4(ipv4));
            }
        }
    }
    local_ips.sort();
    local_ips.dedup();

    Ok(P2pNode {
        swarm,
        stream_control,
        local_ips,
    })
}

pub fn protocol_for_room(room_id: &str) -> StreamProtocol {
    StreamProtocol::try_from_owned(format!("/peerdrop/xfer/{}", room_id))
        .expect("valid protocol name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_base58_roundtrip() {
        let ticket = Ticket {
            c: "4821-cosmic-falcon".to_string(),
            a: vec!["/ip4/192.168.1.10/tcp/50000".to_string()],
        };
        let b58 = ticket.to_base58().unwrap();
        assert!(b58.starts_with("pd1_"));

        let parsed = Ticket::from_str(&b58).unwrap();
        assert_eq!(parsed.c, ticket.c);
        assert_eq!(parsed.a, ticket.a);
    }

    #[test]
    fn test_ticket_from_raw_code() {
        let ticket = Ticket::from_str("4821-cosmic-falcon").unwrap();
        assert_eq!(ticket.c, "4821-cosmic-falcon");
        assert!(ticket.a.is_empty());
    }

    #[test]
    fn test_ticket_from_code_at_ipv4() {
        let ticket = Ticket::from_str("my-code@192.168.1.50:8080").unwrap();
        assert_eq!(ticket.c, "my-code");
        assert_eq!(ticket.a, vec!["/ip4/192.168.1.50/tcp/8080"]);
    }

    #[test]
    fn test_ticket_from_code_at_ipv6() {
        let ticket = Ticket::from_str("my-code@[::1]:9000").unwrap();
        assert_eq!(ticket.c, "my-code");
        assert_eq!(ticket.a, vec!["/ip6/::1/tcp/9000"]);
    }

    #[test]
    fn test_ticket_from_code_at_multiaddr() {
        let ticket = Ticket::from_str("my-code@/ip4/127.0.0.1/tcp/9999").unwrap();
        assert_eq!(ticket.c, "my-code");
        assert_eq!(ticket.a, vec!["/ip4/127.0.0.1/tcp/9999"]);
    }

    #[test]
    fn test_ticket_empty_rejected() {
        assert!(Ticket::from_str("").is_err());
        assert!(Ticket::from_str("   ").is_err());
        assert!(Ticket::from_str("@192.168.1.1:8080").is_err());
        assert!(Ticket::from_str("code@invalid_addr").is_err());
    }
}
