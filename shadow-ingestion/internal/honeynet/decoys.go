// Package honeynet runs a deceptive layer of synthetic "decoy" aircraft
// alongside real ADS-B traffic. Decoys are written into the same Redis
// caches as legitimate aircraft (key prefix `aircraft:` and the geo set
// `aircraft:positions`), so any caller scraping that cache also scrapes
// the decoys.
//
// Detection model: a decoy ICAO24 has zero legitimate reason to be
// observed in the wild. If a packet flows through extractFeatures /
// enrichPacket carrying a decoy ICAO24, OR if an API caller queries one
// of these IDs, that is treated as recon / insider abuse — the
// associated SrcIP is moved into the threat-intel cache with a high
// confidence score, and the gossip mesh broadcasts it to all peer
// ingestion instances.
//
// Decoy IDs use ICAO24 prefix `DEC` (3 hex chars) which is reserved
// for ICAO test allocations and never appears on real aircraft. The
// prefix doubles as an O(1) check.
package honeynet

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"

	"shadow-ndr/ingestion/internal/storage"
)

// DecoyPrefix marks every honeynet ICAO24. Real-world ADS-B beacons
// never start with these three hex chars (ICAO test block).
const DecoyPrefix = "DEC"

var (
	decoyHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadow_honeynet_observed_total",
		Help: "Number of times a decoy aircraft ID surfaced in the pipeline (recon / insider signal).",
	}, []string{"source"}) // source = "packet" | "api"

	decoysActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shadow_honeynet_active_decoys",
		Help: "Currently injected decoy aircraft count.",
	})
)

// Decoy is the shape stored in Redis under `aircraft:<icao24>`.
type Decoy struct {
	ICAO24       string  `json:"icao24"`
	Registration string  `json:"registration"`
	Type         string  `json:"type"`
	Operator     string  `json:"operator"`
	Callsign     string  `json:"callsign"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Altitude     float64 `json:"altitude"`
	Velocity     float64 `json:"velocity"`
	Heading      float64 `json:"heading"`
}

// IsDecoyICAO returns true for any ICAO24 with the honeynet prefix.
// Use this as a fast guard in API handlers and packet processing.
func IsDecoyICAO(icao24 string) bool {
	return len(icao24) >= 3 && strings.EqualFold(icao24[:3], DecoyPrefix)
}

// Worker injects, refreshes and ages-out decoys. Safe for concurrent use.
type Worker struct {
	redis     *storage.RedisClient
	mu        sync.RWMutex
	decoys    map[string]*Decoy
	count     int
	ttl       time.Duration
	tickEvery time.Duration

	OnObservation func(ctx context.Context, icao24, srcIP, source string)
}

// Config controls how aggressive the honeynet is.
type Config struct {
	Count       int           // how many decoys to keep alive (default 12)
	RefreshRate time.Duration // movement update cadence (default 10s)
	TTL         time.Duration // Redis TTL per decoy (default 5m)
}

func New(redis *storage.RedisClient, cfg Config) *Worker {
	if cfg.Count <= 0 {
		cfg.Count = 12
	}
	if cfg.RefreshRate <= 0 {
		cfg.RefreshRate = 10 * time.Second
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	return &Worker{
		redis:     redis,
		decoys:    make(map[string]*Decoy, cfg.Count),
		count:     cfg.Count,
		ttl:       cfg.TTL,
		tickEvery: cfg.RefreshRate,
	}
}

// Run blocks until ctx is cancelled. Spawn it once via safeGo.
func (w *Worker) Run(ctx context.Context) {
	w.seed()
	w.publish(ctx)
	t := time.NewTicker(w.tickEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) seed() {
	w.mu.Lock()
	defer w.mu.Unlock()
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	operators := []string{"ELAL", "ISRAIR", "ARKIA", "DECOY-OPS"}
	types := []string{"B738", "A320", "A21N", "B789"}
	for i := 0; i < w.count; i++ {
		id := fmt.Sprintf("%s%03X", DecoyPrefix, rnd.Intn(0xFFF))
		w.decoys[id] = &Decoy{
			ICAO24:       id,
			Registration: fmt.Sprintf("4X-DCY%d", i),
			Type:         types[rnd.Intn(len(types))],
			Operator:     operators[rnd.Intn(len(operators))],
			Callsign:     fmt.Sprintf("HONEY%03d", i),
			Latitude:     31.0 + rnd.Float64()*2.5,  // Israel airspace box
			Longitude:    34.0 + rnd.Float64()*2.5,
			Altitude:     25000 + rnd.Float64()*15000,
			Velocity:     420 + rnd.Float64()*80,
			Heading:      rnd.Float64() * 360,
		}
	}
	decoysActive.Set(float64(len(w.decoys)))
}

func (w *Worker) tick(ctx context.Context) {
	w.mu.Lock()
	for _, d := range w.decoys {
		// crude great-circle drift: 1 second's worth of movement at altitude
		dt := w.tickEvery.Seconds()
		nm := (d.Velocity * dt) / 3600.0
		brad := d.Heading * math.Pi / 180.0
		d.Latitude += (nm / 60.0) * math.Cos(brad)
		d.Longitude += (nm / 60.0) * math.Sin(brad)
		d.Heading = math.Mod(d.Heading+0.5, 360)
	}
	w.mu.Unlock()
	w.publish(ctx)
}

func (w *Worker) publish(ctx context.Context) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for id, d := range w.decoys {
		if err := w.redis.SetAircraft(ctx, id, d, w.ttl); err != nil {
			log.Debug().Err(err).Str("icao24", id).Msg("honeynet: SetAircraft failed")
			continue
		}
		_ = w.redis.GeoAdd(ctx, "aircraft:positions", d.Longitude, d.Latitude, id)
	}
}

// All returns a snapshot of currently-active decoy IDs.
func (w *Worker) All() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	ids := make([]string, 0, len(w.decoys))
	for id := range w.decoys {
		ids = append(ids, id)
	}
	return ids
}

// Observe records a decoy interaction. `source` is "packet" (real ADS-B
// stream carrying a decoy ID — extremely rare, points to spoofing) or
// "api" (a backend caller queried the decoy — recon / insider).
//
// The associated callback (set on the Worker) lets ProcessorState push
// the SrcIP into threat-intel + gossip without this package importing
// either.
func (w *Worker) Observe(ctx context.Context, icao24, srcIP, source string) {
	if !IsDecoyICAO(icao24) {
		return
	}
	decoyHits.WithLabelValues(source).Inc()
	log.Warn().
		Str("icao24", icao24).
		Str("src_ip", srcIP).
		Str("source", source).
		Msg("HONEYNET: decoy aircraft observed — possible recon")
	if w.OnObservation != nil {
		w.OnObservation(ctx, icao24, srcIP, source)
	}
}

// PubSubBridge subscribes to a Redis keyspace channel that emits every
// GET on a decoy aircraft key. Wire this to a Redis instance with
// `notify-keyspace-events KEA` to detect API observers without
// cooperation from the API server. Optional.
func (w *Worker) PubSubBridge(ctx context.Context, client *redis.Client) {
	pattern := "__keyspace@*__:aircraft:" + DecoyPrefix + "*"
	sub := client.PSubscribe(ctx, pattern)
	defer sub.Close()
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			if msg == nil {
				return
			}
			// Channel name carries the key; we don't have the SrcIP here,
			// but emit a generic recon event.
			parts := strings.Split(msg.Channel, ":")
			id := parts[len(parts)-1]
			w.Observe(ctx, id, "<keyspace>", "api")
		}
	}
}

// MarshalSnapshot returns a JSON snapshot of every active decoy. Useful
// for the /honeynet/snapshot debug endpoint.
func (w *Worker) MarshalSnapshot() ([]byte, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]*Decoy, 0, len(w.decoys))
	for _, d := range w.decoys {
		out = append(out, d)
	}
	return json.Marshal(out)
}
