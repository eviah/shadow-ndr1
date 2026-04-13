package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/rs/zerolog/log"

	"shadow-ndr/ingestion/internal/models"
)

type ClickHouseClient struct {
	conn      driver.Conn
	tableName string
}

func NewClickHouse(host string, port int, database, user, password string) (*ClickHouseClient, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", host, port)},
		Auth: clickhouse.Auth{
			Database: database,
			Username: user,
			Password: password,
		},
		DialTimeout:     10 * time.Second,
		Compression:     &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
		MaxOpenConns:    20,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	log.Info().Msg("Connected to ClickHouse (Aviation Edition)")

	client := &ClickHouseClient{conn: conn, tableName: "aviation_packets"}

	if err := client.createTable(ctx); err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}
	return client, nil
}

func (c *ClickHouseClient) createTable(ctx context.Context) error {
	// Extended schema with all aviation fields (no railway)
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			timestamp DateTime64(3) CODEC(Delta, LZ4),
			src_ip String,
			dst_ip String,
			src_port UInt16,
			dst_port UInt16,
			proto UInt8,
			size UInt16,

			-- Protocol identification
			protocol String,
			parsed_data String CODEC(ZSTD(3)),

			-- Core security
			attack_types String,
			score Float32,
			is_critical UInt8,
			threat_score Float32,

			-- Aviation
			icao24 String,
			callsign String,
			flight_number String,
			aircraft_type String,
			latitude Float64,
			longitude Float64,
			altitude Float32,
			velocity Float32,
			heading Float32,
			vertical_rate Float32,
			squawk UInt16,

			-- Avionics bus (ARINC 429 / AFDX)
			avionics_bus String,
			bus_label UInt8,
			bus_sdi UInt8,
			bus_data UInt32,
			bus_ssm UInt8,

			-- ACARS
			acars_mode String,
			acars_text String,
			acars_aircraft String,

			-- Generic
			org_id String,
			tags Array(String),

			-- Indexes
			INDEX idx_icao24 icao24 TYPE bloom_filter GRANULARITY 1,
			INDEX idx_callsign callsign TYPE bloom_filter GRANULARITY 1,
			INDEX idx_score score TYPE set(100) GRANULARITY 1,
			INDEX idx_attack_types attack_types TYPE bloom_filter GRANULARITY 1
		) ENGINE = MergeTree()
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (timestamp, org_id, icao24, src_ip)
		SETTINGS index_granularity = 8192;
	`, c.tableName)

	return c.conn.Exec(ctx, query)
}

func (c *ClickHouseClient) InsertBatch(ctx context.Context, packets []models.ParsedPacket) error {
	if len(packets) == 0 {
		return nil
	}

	batch, err := c.conn.PrepareBatch(ctx, fmt.Sprintf(`
		INSERT INTO %s (
			timestamp, src_ip, dst_ip, src_port, dst_port, proto, size,
			protocol, parsed_data, attack_types, score, is_critical, threat_score,
			icao24, callsign, flight_number, aircraft_type, latitude, longitude,
			altitude, velocity, heading, vertical_rate, squawk,
			avionics_bus, bus_label, bus_sdi, bus_data, bus_ssm,
			acars_mode, acars_text, acars_aircraft,
			org_id, tags
		)`, c.tableName))

	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	for _, p := range packets {
		parsedJSON, _ := json.Marshal(p.ParsedData)
		attackJSON, _ := json.Marshal(p.AttackTypes)
		tagsJSON, _ := json.Marshal(p.Tags)

		if err := batch.Append(
			p.Timestamp,
			p.SrcIP,
			p.DstIP,
			p.SrcPort,
			p.DstPort,
			p.Proto,
			p.Size,
			p.Protocol,
			string(parsedJSON),
			string(attackJSON),
			p.Score,
			boolToUint8(p.IsCritical),
			p.ThreatScore,
			nullableString(p.ICAO24),
			nullableString(p.Callsign),
			nullableString(p.FlightNumber),
			nullableString(p.AircraftType),
			nullableFloat64(p.Latitude),
			nullableFloat64(p.Longitude),
			nullableFloat32(p.Altitude),
			nullableFloat32(p.Velocity),
			nullableFloat32(p.Heading),
			nullableFloat32(p.VerticalRate),
			nullableUint16(p.Squawk),
			p.AvionicsBus,
			nullableUint8(p.BusLabel),
			nullableUint8(p.BusSDI),
			nullableUint32(p.BusData),
			nullableUint8(p.BusSSM),
			nullableString(p.ACARSMode),
			nullableString(p.ACARSText),
			nullableString(p.ACARSAircraft),
			p.OrgID,
			string(tagsJSON),
		); err != nil {
			return fmt.Errorf("append to batch: %w", err)
		}
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("send batch: %w", err)
	}
	log.Debug().Int("count", len(packets)).Msg("Inserted batch into ClickHouse")
	return nil
}

func (c *ClickHouseClient) Ping(ctx context.Context) error {
	return c.conn.Ping(ctx)
}

func (c *ClickHouseClient) Close() error {
	return c.conn.Close()
}

// Helpers for nullable values
func nullableString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
func nullableFloat64(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}
func nullableFloat32(f *float32) float32 {
	if f == nil {
		return 0
	}
	return *f
}
func nullableUint16(u *uint16) uint16 {
	if u == nil {
		return 0
	}
	return *u
}
func nullableUint8(u *uint8) uint8 {
	if u == nil {
		return 0
	}
	return *u
}
func nullableUint32(u *uint32) uint32 {
	if u == nil {
		return 0
	}
	return *u
}

// boolToUint8 converts a boolean to uint8 (1 for true, 0 for false)
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
