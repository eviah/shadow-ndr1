//! Unified packet parser – dispatches to protocol‑specific parsers

use bytes::Bytes;
use serde::Serialize;
use std::collections::HashMap;
use anyhow::{Context, Result};
use etherparse::{Ethernet2Header, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::protocols::*;

#[derive(Debug, Clone, Serialize)]
pub struct ParsedPacket {
    pub protocol: String,
    pub timestamp: DateTime<Utc>,
    pub flow_id: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub threat_level: Option<String>,
    pub details: Value,
}

// -----------------------------------------------------------------------------
// Public entry point
// -----------------------------------------------------------------------------
pub fn parse_packet(data: &Bytes, enabled: &HashMap<String, bool>) -> Option<ParsedPacket> {
    // 1. Parse Ethernet + IP headers
    let (ip_info, transport_info) = match parse_ethernet_ip(data) {
        Ok(info) => info,
        Err(_) => return None,
    };

    // 2. If we have transport layer info, try TCP/UDP/ICMP parsers
    if let Some(transport) = transport_info {
        match transport.protocol {
            Protocol::Tcp => {
                if *enabled.get("tcp").unwrap_or(&true) {
                    if let Some(pkt) = parse_tcp_packet(data, &ip_info, &transport) {
                        return Some(pkt);
                    }
                }
            }
            Protocol::Udp => {
                if *enabled.get("udp").unwrap_or(&true) {
                    if let Some(pkt) = parse_udp_packet(data, &ip_info, &transport) {
                        return Some(pkt);
                    }
                }
                // DNS / DHCP / RTP over UDP
                if *enabled.get("dns").unwrap_or(&true) {
                    if let Some(pkt) = parse_dns_packet(data, &ip_info, &transport) {
                        return Some(pkt);
                    }
                }
                if *enabled.get("dhcp").unwrap_or(&true) {
                    if let Some(pkt) = parse_dhcp_packet(data, &ip_info, &transport) {
                        return Some(pkt);
                    }
                }
                if *enabled.get("rtp").unwrap_or(&true) {
                    if let Some(pkt) = parse_rtp_packet(data, &ip_info, &transport) {
                        return Some(pkt);
                    }
                }
            }
            Protocol::Icmp => {
                if *enabled.get("icmp").unwrap_or(&true) {
                    if let Some(pkt) = parse_icmp_packet(data, &ip_info, &transport) {
                        return Some(pkt);
                    }
                }
            }
            Protocol::Other => { /* try payload-based parsers below */ }
        }

        // 3. Try application‑level protocols using the actual payload
        if let Some(payload) = get_payload_from_transport(data, &transport) {
            // MQTT
            if *enabled.get("mqtt").unwrap_or(&true) && payload.len() > 2 {
                if let Some(pkt) = parse_mqtt_packet(payload, &ip_info) {
                    return Some(pkt);
                }
            }
            // AMQP
            if *enabled.get("amqp").unwrap_or(&true) && payload.len() > 8 {
                if let Some(pkt) = parse_amqp_packet(payload, &ip_info) {
                    return Some(pkt);
                }
            }
            // Modbus
            if *enabled.get("modbus").unwrap_or(&true) && payload.len() >= 6 {
                if let Some(pkt) = parse_modbus_packet(payload, &ip_info) {
                    return Some(pkt);
                }
            }
            // DNP3
            if *enabled.get("dnp3").unwrap_or(&true) && payload.len() >= 10 {
                if let Some(pkt) = parse_dnp3_packet(payload, &ip_info) {
                    return Some(pkt);
                }
            }
            // SIP (text‑based, starts with "SIP/")
            if *enabled.get("sip").unwrap_or(&true) && payload.len() > 4 && &payload[0..4] == b"SIP/" {
                if let Some(pkt) = parse_sip_packet(payload, &ip_info) {
                    return Some(pkt);
                }
            }
        }
    }

    // 4. Aviation protocols (ADS‑B, ACARS, etc.) – keep existing from shadow-parsers
    #[cfg(feature = "aviation")]
    {
        if let Some(pkt) = parse_aviation_packet(data, enabled) {
            return Some(pkt);
        }
    }

    None
}

// -----------------------------------------------------------------------------
// Helper: Ethernet + IP parsing (correctly uses etherparse::from_slice)
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct EthernetIpInfo {
    pub src_ip: String,
    pub dst_ip: String,
    pub ip_proto: u8,
    pub transport_offset: usize,   // offset where transport header (TCP/UDP/ICMP) starts
}

#[derive(Clone, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

#[derive(Clone)]
pub struct TransportInfo {
    pub protocol: Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub payload_offset: usize,     // offset where actual application payload starts
}

fn parse_ethernet_ip(data: &Bytes) -> Result<(EthernetIpInfo, Option<TransportInfo>)> {
    if data.len() < 14 {
        anyhow::bail!("Packet too short for Ethernet header");
    }

    let eth = Ethernet2Header::from_slice(&data[0..14])?;
    let ether_type = eth.0.ether_type;
    let ip_start = 14;

    // ---------- IPv4 ----------
    if ether_type == 0x0800 {
        let ip_header = Ipv4Header::from_slice(&data[ip_start..])
            .context("Failed to parse IPv4 header")?;
        // תיקון: גישה לשדות דרך .0
        let src_ip = format!(
            "{}.{}.{}.{}",
            ip_header.0.source[0], ip_header.0.source[1],
            ip_header.0.source[2], ip_header.0.source[3]
        );
        let dst_ip = format!(
            "{}.{}.{}.{}",
            ip_header.0.destination[0], ip_header.0.destination[1],
            ip_header.0.destination[2], ip_header.0.destination[3]
        );
        let ip_proto = ip_header.0.protocol;
        let ip_header_len = ip_header.0.header_len() as usize;
        let transport_start = ip_start + ip_header_len;

        let transport_info = match ip_proto {
            6 => { // TCP
                if data.len() >= transport_start + 20 {
                    let tcp = TcpHeader::from_slice(&data[transport_start..])?;
                    Some(TransportInfo {
                        protocol: Protocol::Tcp,
                        src_port: Some(tcp.0.source_port),
                        dst_port: Some(tcp.0.destination_port),
                        payload_offset: transport_start + tcp.0.header_len() as usize,
                    })
                } else {
                    None
                }
            }
            17 => { // UDP
                if data.len() >= transport_start + 8 {
                    let udp = UdpHeader::from_slice(&data[transport_start..])?;
                    Some(TransportInfo {
                        protocol: Protocol::Udp,
                        src_port: Some(udp.0.source_port),
                        dst_port: Some(udp.0.destination_port),
                        payload_offset: transport_start + 8,
                    })
                } else {
                    None
                }
            }
            1 => { // ICMP
                Some(TransportInfo {
                    protocol: Protocol::Icmp,
                    src_port: None,
                    dst_port: None,
                    payload_offset: transport_start,
                })
            }
            _ => None,
        };

        Ok((
            EthernetIpInfo {
                src_ip,
                dst_ip,
                ip_proto,
                transport_offset: transport_start,
            },
            transport_info,
        ))
    }
    // ---------- IPv6 ----------
    else if ether_type == 0x86DD {
        let ip_header = Ipv6Header::from_slice(&data[ip_start..])
            .context("Failed to parse IPv6 header")?;
        // תיקון: גישה לשדות דרך .0
        let src_ip = format!(
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            ((ip_header.0.source[0] as u16) << 8) | ip_header.0.source[1] as u16,
            ((ip_header.0.source[2] as u16) << 8) | ip_header.0.source[3] as u16,
            ((ip_header.0.source[4] as u16) << 8) | ip_header.0.source[5] as u16,
            ((ip_header.0.source[6] as u16) << 8) | ip_header.0.source[7] as u16,
            ((ip_header.0.source[8] as u16) << 8) | ip_header.0.source[9] as u16,
            ((ip_header.0.source[10] as u16) << 8) | ip_header.0.source[11] as u16,
            ((ip_header.0.source[12] as u16) << 8) | ip_header.0.source[13] as u16,
            ((ip_header.0.source[14] as u16) << 8) | ip_header.0.source[15] as u16
        );
        let dst_ip = format!(
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            ((ip_header.0.destination[0] as u16) << 8) | ip_header.0.destination[1] as u16,
            ((ip_header.0.destination[2] as u16) << 8) | ip_header.0.destination[3] as u16,
            ((ip_header.0.destination[4] as u16) << 8) | ip_header.0.destination[5] as u16,
            ((ip_header.0.destination[6] as u16) << 8) | ip_header.0.destination[7] as u16,
            ((ip_header.0.destination[8] as u16) << 8) | ip_header.0.destination[9] as u16,
            ((ip_header.0.destination[10] as u16) << 8) | ip_header.0.destination[11] as u16,
            ((ip_header.0.destination[12] as u16) << 8) | ip_header.0.destination[13] as u16,
            ((ip_header.0.destination[14] as u16) << 8) | ip_header.0.destination[15] as u16
        );
        let ip_proto = ip_header.0.next_header;
        let transport_start = ip_start + 40;

        let transport_info = match ip_proto {
            6 => { // TCP
                if data.len() >= transport_start + 20 {
                    let tcp = TcpHeader::from_slice(&data[transport_start..])?;
                    Some(TransportInfo {
                        protocol: Protocol::Tcp,
                        src_port: Some(tcp.0.source_port),
                        dst_port: Some(tcp.0.destination_port),
                        payload_offset: transport_start + tcp.0.header_len() as usize,
                    })
                } else {
                    None
                }
            }
            17 => { // UDP
                if data.len() >= transport_start + 8 {
                    let udp = UdpHeader::from_slice(&data[transport_start..])?;
                    Some(TransportInfo {
                        protocol: Protocol::Udp,
                        src_port: Some(udp.0.source_port),
                        dst_port: Some(udp.0.destination_port),
                        payload_offset: transport_start + 8,
                    })
                } else {
                    None
                }
            }
            58 => { // ICMPv6
                Some(TransportInfo {
                    protocol: Protocol::Icmp,
                    src_port: None,
                    dst_port: None,
                    payload_offset: transport_start,
                })
            }
            _ => None,
        };

        Ok((
            EthernetIpInfo {
                src_ip,
                dst_ip,
                ip_proto,
                transport_offset: transport_start,
            },
            transport_info,
        ))
    } else {
        anyhow::bail!("Not an IPv4 or IPv6 packet (ether_type = 0x{:04x})", ether_type);
    }
}

/// Extract the application payload from the transport info (if any)
fn get_payload_from_transport<'a>(data: &'a Bytes, transport: &TransportInfo) -> Option<&'a [u8]> {
    if data.len() > transport.payload_offset {
        Some(&data[transport.payload_offset..])
    } else {
        None
    }
}