use bytes::Bytes;
use crate::parser::{ParsedPacket, EthernetIpInfo, TransportInfo};
use chrono::Utc;
use serde_json::json;

pub fn parse_tcp_packet(_data: &Bytes, ip: &EthernetIpInfo, transport: &TransportInfo) -> Option<ParsedPacket> {
    let src_port = transport.src_port?;
    let dst_port = transport.dst_port?;
    
    Some(ParsedPacket {
        protocol: "tcp".to_string(),
        timestamp: Utc::now(),
        flow_id: format!("{}:{}->{}:{}", ip.src_ip, src_port, ip.dst_ip, dst_port),
        src_ip: ip.src_ip.clone(),      // ip.src_ip הוא String, לא Option
        dst_ip: ip.dst_ip.clone(),      // ip.dst_ip הוא String, לא Option
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        threat_level: None,
        details: json!({ "src_port": src_port, "dst_port": dst_port }),
    })
}