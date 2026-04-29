// Package gossip turns every ingestion instance into a node in a fan-out
// mesh of high-confidence threat sightings.
//
// Each node:
//   - PUBLISHES on `ndr:gossip:threats` whenever enrichPacket sees a
//     score above HighConfidence (default 0.85).
//   - SUBSCRIBES to the same channel and merges every peer's broadcast
//     into its in-memory threat-intel cache, so an attacker who lights
//     up node A is immediately blacklisted on B, C, D, ...
//
// Loop-back is suppressed by a per-node UUID embedded in each event and
// short-TTL (60s) deduplication based on event ID. The channel uses
// JSON-encoded events (small, easy to inspect with `redis-cli MONITOR`).
package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// Channel is the Redis Pub/Sub channel used by the mesh.
const Channel = "ndr:gossip:threats"

// HighConfidence is the score threshold above which findings are
// gossiped. Tunable from config; this is the default.
const HighConfidence = 0.85

var (
	gossipPublished = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_gossip_published_total",
		Help: "Threat events broadcast onto the gossip mesh.",
	})
	gossipReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_gossip_received_total",
		Help: "Threat events received from peer ingestion nodes.",
	})
	gossipDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadow_gossip_dropped_total",
		Help: "Gossip events dropped (loop, dup, malformed).",
	}, []string{"reason"})
)

// Event is what travels on the wire.
type Event struct {
	ID         string    `json:"id"`
	Origin     string    `json:"origin"`
	IP         string    `json:"ip,omitempty"`
	ICAO24     string    `json:"icao24,omitempty"`
	Score      float64   `json:"score"`
	ThreatType string    `json:"threat_type,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Timestamp  time.Time `json:"ts"`
}

// Sink absorbs incoming threat sightings from peer nodes. Anything that
// implements `Add` (e.g. ThreatIntelCache) qualifies.
type Sink interface {
	Add(ip, icao24, threatType, source string, score float64)
}

// Mesh is a single node's participation in the gossip channel.
type Mesh struct {
	rdb    *redis.Client
	nodeID string
	sink   Sink

	mu    sync.Mutex
	dedup map[string]time.Time
}

// New builds a Mesh. The redis client passed in MUST be the underlying
// *redis.Client from go-redis (storage.RedisClient.Raw() exposes it),
// because Pub/Sub needs methods our wrapper does not expose.
func New(rdb *redis.Client, sink Sink) *Mesh {
	return &Mesh{
		rdb:    rdb,
		nodeID: uuid.NewString(),
		sink:   sink,
		dedup:  make(map[string]time.Time),
	}
}

// Run subscribes to the channel and feeds every peer event into the
// configured Sink. Blocks until ctx is cancelled. Spawn under safeGo.
func (m *Mesh) Run(ctx context.Context) {
	sub := m.rdb.Subscribe(ctx, Channel)
	defer sub.Close()
	ch := sub.Channel()
	gc := time.NewTicker(60 * time.Second)
	defer gc.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-gc.C:
			m.gcDedup()
		case msg, ok := <-ch:
			if !ok {
				return
			}
			m.ingest(msg)
		}
	}
}

func (m *Mesh) ingest(msg *redis.Message) {
	if msg == nil {
		return
	}
	var ev Event
	if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
		gossipDropped.WithLabelValues("malformed").Inc()
		return
	}
	if ev.Origin == m.nodeID {
		gossipDropped.WithLabelValues("loopback").Inc()
		return
	}
	if !m.markSeen(ev.ID) {
		gossipDropped.WithLabelValues("duplicate").Inc()
		return
	}
	gossipReceived.Inc()
	if m.sink != nil {
		m.sink.Add(ev.IP, ev.ICAO24, ev.ThreatType, "gossip:"+ev.Origin[:8], ev.Score)
	}
	log.Info().
		Str("origin", ev.Origin[:8]).
		Str("ip", ev.IP).
		Str("icao24", ev.ICAO24).
		Float64("score", ev.Score).
		Str("type", ev.ThreatType).
		Msg("gossip: peer threat ingested")
}

// Publish broadcasts a high-confidence sighting to every peer.
func (m *Mesh) Publish(ctx context.Context, ev Event) error {
	if ev.Score < HighConfidence {
		return nil
	}
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.Origin == "" {
		ev.Origin = m.nodeID
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	m.markSeen(ev.ID) // suppress our own echo
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if err := m.rdb.Publish(ctx, Channel, payload).Err(); err != nil {
		return fmt.Errorf("gossip publish: %w", err)
	}
	gossipPublished.Inc()
	return nil
}

// NodeID returns this instance's gossip identity.
func (m *Mesh) NodeID() string { return m.nodeID }

// ─── dedup helpers ──────────────────────────────────────────────────────────

func (m *Mesh) markSeen(id string) bool {
	if id == "" {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.dedup[id]; ok {
		return false
	}
	m.dedup[id] = time.Now()
	return true
}

func (m *Mesh) gcDedup() {
	cutoff := time.Now().Add(-60 * time.Second)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, ts := range m.dedup {
		if ts.Before(cutoff) {
			delete(m.dedup, id)
		}
	}
}
