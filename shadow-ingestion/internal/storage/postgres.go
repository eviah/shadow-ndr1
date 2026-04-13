package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"shadow-ndr/ingestion/internal/models"
)

type PostgresClient struct {
	pool *pgxpool.Pool
}

func NewPostgres(host string, port int, database, user, password string) (*PostgresClient, error) {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		user, password, host, port, database)
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	config.MaxConns = 20
	config.MinConns = 5
	config.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}

	log.Info().Msg("Connected to PostgreSQL (Aviation Edition)")

	client := &PostgresClient{pool: pool}
	if err := client.createTables(ctx); err != nil {
		return nil, fmt.Errorf("create tables: %w", err)
	}
	return client, nil
}

func (p *PostgresClient) createTables(ctx context.Context) error {
	queries := []string{
		// Aircraft registry table
		`CREATE TABLE IF NOT EXISTS aircraft (
			icao24 TEXT PRIMARY KEY,
			registration TEXT,
			aircraft_type TEXT,
			manufacturer TEXT,
			operator TEXT,
			first_seen TIMESTAMPTZ,
			last_seen TIMESTAMPTZ,
			metadata JSONB
		)`,

		// Flights table
		`CREATE TABLE IF NOT EXISTS flights (
			id BIGSERIAL PRIMARY KEY,
			callsign TEXT,
			flight_number TEXT,
			icao24 TEXT REFERENCES aircraft(icao24),
			departure_airport TEXT,
			arrival_airport TEXT,
			scheduled_departure TIMESTAMPTZ,
			scheduled_arrival TIMESTAMPTZ,
			actual_departure TIMESTAMPTZ,
			actual_arrival TIMESTAMPTZ,
			flight_plan JSONB,
			status TEXT,
			created_at TIMESTAMPTZ DEFAULT now()
		)`,

		// Main packets table - Aviation only (no railway fields)
		`CREATE TABLE IF NOT EXISTS packets (
			id BIGSERIAL PRIMARY KEY,
			timestamp TIMESTAMPTZ NOT NULL,
			src_ip INET,
			dst_ip INET,
			src_port INT,
			dst_port INT,
			proto SMALLINT,
			size INT,
			protocol TEXT,
			parsed_data JSONB,
			attack_types JSONB,
			score FLOAT,
			is_critical BOOLEAN,
			threat_score FLOAT,
			-- Aviation
			icao24 TEXT REFERENCES aircraft(icao24),
			callsign TEXT,
			flight_number TEXT,
			aircraft_type TEXT,
			latitude DOUBLE PRECISION,
			longitude DOUBLE PRECISION,
			altitude FLOAT,
			velocity FLOAT,
			heading FLOAT,
			vertical_rate FLOAT,
			squawk INT,
			-- Avionics
			avionics_bus TEXT,
			bus_label INT,
			bus_sdi INT,
			bus_data BIGINT,
			bus_ssm INT,
			-- ACARS
			acars_mode TEXT,
			acars_text TEXT,
			acars_aircraft TEXT,
			-- Generic
			org_id TEXT NOT NULL,
			tags TEXT[],
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_packets_icao24 ON packets(icao24)`,
		`CREATE INDEX IF NOT EXISTS idx_packets_callsign ON packets(callsign)`,
		`CREATE INDEX IF NOT EXISTS idx_packets_org ON packets(org_id)`,
		`CREATE INDEX IF NOT EXISTS idx_packets_score ON packets(score) WHERE score > 0.7`,
		`CREATE INDEX IF NOT EXISTS idx_packets_parsed ON packets USING gin(parsed_data)`,
		`CREATE INDEX IF NOT EXISTS idx_packets_attack ON packets USING gin(attack_types)`,

		// Alerts table
		`CREATE TABLE IF NOT EXISTS alerts (
			id BIGSERIAL PRIMARY KEY,
			timestamp TIMESTAMPTZ NOT NULL,
			packet_id BIGINT REFERENCES packets(id),
			severity TEXT NOT NULL,
			message TEXT,
			details JSONB,
			org_id TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)`,

		// Threat intelligence cache
		`CREATE TABLE IF NOT EXISTS threat_intel (
			ip INET PRIMARY KEY,
			score FLOAT,
			category TEXT,
			source TEXT,
			first_seen TIMESTAMPTZ,
			last_seen TIMESTAMPTZ,
			metadata JSONB
		)`,
	}

	for _, q := range queries {
		if _, err := p.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("exec %s: %w", q[:50], err)
		}
	}
	return nil
}

// UpsertBatch uses COPY for high‑performance bulk insert.
// UpsertBatch uses COPY for high‑performance bulk insert.
func (p *PostgresClient) UpsertBatch(ctx context.Context, packets []models.ParsedPacket) error {
	if len(packets) == 0 {
		return nil
	}

	rows := make([][]interface{}, 0, len(packets))
	for _, pkt := range packets {
		rows = append(rows, []interface{}{
			pkt.Timestamp,
			pkt.SrcIP,
			pkt.DstIP,
			pkt.SrcPort,
			pkt.DstPort,
			pkt.Proto,
			pkt.Size,
			pkt.Protocol,
			pkt.ParsedData,
			pkt.AttackTypes,
			pkt.Score,
			pkt.IsCritical,
			pkt.ThreatScore,
			nullableStringPtr(pkt.ICAO24),
			nullableStringPtr(pkt.Callsign),
			nullableStringPtr(pkt.FlightNumber),
			nullableStringPtr(pkt.AircraftType),
			nullableFloat64Ptr(pkt.Latitude),
			nullableFloat64Ptr(pkt.Longitude),
			nullableFloat32Ptr(pkt.Altitude),
			nullableFloat32Ptr(pkt.Velocity),
			nullableFloat32Ptr(pkt.Heading),
			nullableFloat32Ptr(pkt.VerticalRate),
			nullableUint16Ptr(pkt.Squawk),
			pkt.AvionicsBus,
			nullableUint8Ptr(pkt.BusLabel),
			nullableUint8Ptr(pkt.BusSDI),
			nullableUint32Ptr(pkt.BusData),
			nullableUint8Ptr(pkt.BusSSM),
			nullableStringPtr(pkt.ACARSMode),
			nullableStringPtr(pkt.ACARSText),
			nullableStringPtr(pkt.ACARSAircraft),
			pkt.OrgID,
			pkt.Tags,
		})
	}

	_, err := p.pool.CopyFrom(
		ctx,
		pgx.Identifier{"packets"},
		[]string{
			"timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "size",
			"protocol", "parsed_data", "attack_types", "score", "is_critical", "threat_score",
			"icao24", "callsign", "flight_number", "aircraft_type", "latitude", "longitude",
			"altitude", "velocity", "heading", "vertical_rate", "squawk",
			"avionics_bus", "bus_label", "bus_sdi", "bus_data", "bus_ssm",
			"acars_mode", "acars_text", "acars_aircraft",
			"org_id", "tags",
		},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		return fmt.Errorf("copy from: %w", err)
	}

	log.Debug().Int("count", len(packets)).Msg("Upserted batch into PostgreSQL")
	return nil
}

// Helper functions to convert pointers to interface{} for COPY
func nullableStringPtr(s *string) interface{} {
	if s == nil {
		return nil
	}
	return *s
}
func nullableFloat64Ptr(f *float64) interface{} {
	if f == nil {
		return nil
	}
	return *f
}
func nullableFloat32Ptr(f *float32) interface{} {
	if f == nil {
		return nil
	}
	// Convert to float64 for PostgreSQL double precision
	return float64(*f)
}
func nullableUint16Ptr(u *uint16) interface{} {
	if u == nil {
		return nil
	}
	return int(*u)
}
func nullableUint8Ptr(u *uint8) interface{} {
	if u == nil {
		return nil
	}
	return int(*u)
}
func nullableUint32Ptr(u *uint32) interface{} {
	if u == nil {
		return nil
	}
	return int64(*u)
}

func (p *PostgresClient) Close() {
	p.pool.Close()
}

func (p *PostgresClient) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}
