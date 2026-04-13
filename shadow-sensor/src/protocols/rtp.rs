// RTP protocol parser
pub fn parse_rtp_packet(_data: &[u8], _ip: &crate::parser::EthernetIpInfo, _transport: &crate::parser::TransportInfo) -> Option<crate::parser::ParsedPacket> {
    None // TODO: Implement
}