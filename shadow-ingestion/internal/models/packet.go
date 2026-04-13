package models

import (
	"fmt"
	"net"
	"time"
)

type ParsedPacket struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Proto     uint8     `json:"proto"`
	Size      uint16    `json:"size"`

	Protocol   string                 `json:"protocol,omitempty"`
	ParsedData map[string]interface{} `json:"parsed_data,omitempty"`

	AttackTypes   []string `json:"attack_types,omitempty"`
	Score         float64  `json:"score"`
	IsCritical    bool     `json:"is_critical"`
	ThreatScore   float64  `json:"threat_score,omitempty"`
	ThreatType    string   `json:"threat_type,omitempty"`
	ThreatSource  string   `json:"threat_source,omitempty"`
	RateAnomaly   bool     `json:"rate_anomaly,omitempty"`
	PacketRatePPM float64  `json:"packet_rate_ppm,omitempty"`

	// Aviation fields
	ICAO24       *string  `json:"icao24,omitempty"`
	Callsign     *string  `json:"callsign,omitempty"`
	FlightNumber *string  `json:"flight_number,omitempty"`
	AircraftType *string  `json:"aircraft_type,omitempty"`
	Latitude     *float64 `json:"latitude,omitempty"`
	Longitude    *float64 `json:"longitude,omitempty"`
	Altitude     *float32 `json:"altitude,omitempty"`
	Velocity     *float32 `json:"velocity,omitempty"`
	Heading      *float32 `json:"heading,omitempty"`
	VerticalRate *float32 `json:"vertical_rate,omitempty"`
	Squawk       *uint16  `json:"squawk,omitempty"`

	AvionicsBus string  `json:"avionics_bus,omitempty"`
	BusLabel    *uint8  `json:"bus_label,omitempty"`
	BusSDI      *uint8  `json:"bus_sdi,omitempty"`
	BusData     *uint32 `json:"bus_data,omitempty"`
	BusSSM      *uint8  `json:"bus_ssm,omitempty"`

	ACARSMode     *string `json:"acars_mode,omitempty"`
	ACARSText     *string `json:"acars_text,omitempty"`
	ACARSAircraft *string `json:"acars_aircraft,omitempty"`

	OrgID     string   `json:"org_id"`
	UserID    string   `json:"user_id"`
	SessionID string   `json:"session_id,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

func (p *ParsedPacket) Validate() error {
	if p.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is missing")
	}
	if net.ParseIP(p.SrcIP) == nil {
		return fmt.Errorf("invalid source IP: %q", p.SrcIP)
	}
	if net.ParseIP(p.DstIP) == nil {
		return fmt.Errorf("invalid destination IP: %q", p.DstIP)
	}
	if p.SrcPort > 65535 || p.DstPort > 65535 {
		return fmt.Errorf("port out of range")
	}
	if p.Proto != 0 && p.Proto != 1 && p.Proto != 6 && p.Proto != 17 {
		return fmt.Errorf("unsupported protocol: %d", p.Proto)
	}
	if p.Score < 0 || p.Score > 1 {
		return fmt.Errorf("score out of range: %f", p.Score)
	}
	if p.ThreatScore < 0 || p.ThreatScore > 1 {
		return fmt.Errorf("threat score out of range: %f", p.ThreatScore)
	}
	return nil
}

func (p *ParsedPacket) Normalize() {
	if p.Timestamp.IsZero() {
		p.Timestamp = time.Now().UTC()
	}
	if p.Score < 0 {
		p.Score = 0
	}
	if p.Score > 1 {
		p.Score = 1
	}
	if p.ThreatScore < 0 {
		p.ThreatScore = 0
	}
	if p.ThreatScore > 1 {
		p.ThreatScore = 1
	}
	if p.Proto == 0 {
		p.Proto = 6
	}
	if p.OrgID == "" {
		p.OrgID = "default"
	}
	if p.AttackTypes == nil {
		p.AttackTypes = []string{}
	}
	if p.ParsedData == nil {
		p.ParsedData = make(map[string]interface{})
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}
}

func (p *ParsedPacket) IsHighRisk() bool {
	return p.Score > 0.8 || p.ThreatScore > 0.8
}

func (p *ParsedPacket) Severity() string {
	if p.IsCritical {
		return "CRITICAL"
	}
	if p.Score > 0.9 {
		return "HIGH"
	}
	if p.Score > 0.7 {
		return "MEDIUM"
	}
	if p.Score > 0.3 {
		return "LOW"
	}
	return "INFO"
}

func (p *ParsedPacket) String() string {
	return fmt.Sprintf("%s %s:%d -> %s:%d proto=%d size=%d score=%.3f",
		p.Timestamp.Format(time.RFC3339Nano),
		p.SrcIP, p.SrcPort,
		p.DstIP, p.DstPort,
		p.Proto, p.Size,
		p.Score,
	)
}
