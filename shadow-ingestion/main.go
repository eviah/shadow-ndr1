package main

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Shadow NDR — Ingestion Service  v5.0  «Aviation Ultimate Edition»     ║
// ║  Avionics / ADS-B / ACARS / ARINC 429 / AFDX · Production-grade Go     ║
// ╚══════════════════════════════════════════════════════════════════════════╝

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IBM/sarama"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sony/gobreaker"
	"github.com/spf13/viper"
	"math"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"shadow-ndr/ingestion/internal/kafka"
	"shadow-ndr/ingestion/internal/ml"
	"shadow-ndr/ingestion/internal/models"
	"shadow-ndr/ingestion/internal/parser"
	"shadow-ndr/ingestion/internal/storage"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

type Config struct {
	Kafka struct {
		Brokers        []string      `mapstructure:"brokers"`
		Topic          string        `mapstructure:"topic"`
		DLQTopic       string        `mapstructure:"dlq_topic"`
		GroupID        string        `mapstructure:"group_id"`
		MaxRetries     int           `mapstructure:"max_retries"`
		RetryBaseDelay time.Duration `mapstructure:"retry_base_delay"`
	} `mapstructure:"kafka"`

	ClickHouse struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		Database string `mapstructure:"database"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
	} `mapstructure:"clickhouse"`

	Postgres struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		Database string `mapstructure:"database"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
	} `mapstructure:"postgres"`

	Redis struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`

	ML struct {
		URL              string        `mapstructure:"url"`
		Timeout          time.Duration `mapstructure:"timeout"`
		CacheTTL         time.Duration `mapstructure:"cache_ttl"`
		ExplainThreshold float64       `mapstructure:"explain_threshold"`
		UpdateEnabled    bool          `mapstructure:"update_enabled"`
	} `mapstructure:"ml"`

	CircuitBreaker struct {
		MaxRequests  uint32        `mapstructure:"max_requests"`
		Interval     time.Duration `mapstructure:"interval"`
		Timeout      time.Duration `mapstructure:"timeout"`
		FailureRatio float64       `mapstructure:"failure_ratio"`
	} `mapstructure:"circuit_breaker"`

	Processor struct {
		BatchSize         int           `mapstructure:"batch_size"`
		MaxBatchSize      int           `mapstructure:"max_batch_size"`
		FlushInterval     time.Duration `mapstructure:"flush_interval"`
		RedisTTL          time.Duration `mapstructure:"redis_ttl"`
		WorkerCount       int           `mapstructure:"worker_count"`
		ShutdownTimeout   time.Duration `mapstructure:"shutdown_timeout"`
		RateLimitInterval time.Duration `mapstructure:"rate_limit_interval"`
	} `mapstructure:"processor"`

	Alerting struct {
		CriticalThreshold float64 `mapstructure:"critical_threshold"`
		SOARWebhook       string  `mapstructure:"soar_webhook"`
	} `mapstructure:"alerting"`

	Tracing struct {
		Enabled     bool   `mapstructure:"enabled"`
		Endpoint    string `mapstructure:"endpoint"`
		ServiceName string `mapstructure:"service_name"`
	} `mapstructure:"tracing"`

	Aviation struct {
		EnableADSBCheck      bool     `mapstructure:"enable_adsb_check"`
		EmergencySquawk      []uint16 `mapstructure:"emergency_squawk"`
		MaxAltitudeDeviation float64  `mapstructure:"max_altitude_deviation"`
	} `mapstructure:"aviation"`

	MetricsPort int    `mapstructure:"metrics_port"`
	LogLevel    string `mapstructure:"log_level"`
	Environment string `mapstructure:"environment"`
}

func loadConfig() *Config {
	v := viper.New()
	v.SetDefault("kafka.brokers", []string{"localhost:9092"})
	v.SetDefault("kafka.topic", "shadow.raw")
	v.SetDefault("kafka.dlq_topic", "shadow.dlq")
	v.SetDefault("kafka.group_id", "shadow-ingestion")
	v.SetDefault("kafka.max_retries", 3)
	v.SetDefault("kafka.retry_base_delay", "200ms")

	v.SetDefault("ml.url", "http://localhost:8001")
	v.SetDefault("ml.timeout", "2s")
	v.SetDefault("ml.cache_ttl", "30s")
	v.SetDefault("ml.explain_threshold", 0.75)
	v.SetDefault("ml.update_enabled", true)

	v.SetDefault("circuit_breaker.max_requests", 3)
	v.SetDefault("circuit_breaker.interval", "10s")
	v.SetDefault("circuit_breaker.timeout", "30s")
	v.SetDefault("circuit_breaker.failure_ratio", 0.5)

	v.SetDefault("processor.batch_size", 100)
	v.SetDefault("processor.max_batch_size", 2000)
	v.SetDefault("processor.flush_interval", "5s")
	v.SetDefault("processor.redis_ttl", "5m")
	v.SetDefault("processor.worker_count", 4)
	v.SetDefault("processor.shutdown_timeout", "30s")
	v.SetDefault("processor.rate_limit_interval", "1m")

	v.SetDefault("alerting.critical_threshold", 0.85)
	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.service_name", "shadow-ingestion")
	v.SetDefault("metrics_port", 9090)
	v.SetDefault("log_level", "info")
	v.SetDefault("environment", "production")

	v.SetDefault("aviation.enable_adsb_check", true)
	v.SetDefault("aviation.emergency_squawk", []uint16{7700, 7600, 7500})
	v.SetDefault("aviation.max_altitude_deviation", 5000.0)

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/shadow-ndr/")
	_ = v.ReadInConfig()

	v.SetEnvPrefix("SHADOW")
	v.AutomaticEnv()

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		log.Fatal().Err(err).Msg("Failed to unmarshal config")
	}
	return cfg
}

// ----------------------------------------------------------------------------
// Prometheus Metrics
// ----------------------------------------------------------------------------
var (
	packetsProcessed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadow_packets_processed_total",
		Help: "Total packets processed by outcome.",
	}, []string{"outcome"})

	processingLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "shadow_processing_duration_seconds",
		Help:    "End-to-end packet processing latency.",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1.0, 2.5},
	}, []string{"stage"})

	mlScoreHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "shadow_ml_score",
		Help:    "Distribution of ML anomaly scores.",
		Buckets: []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
	})

	mlCacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_ml_cache_hits_total",
		Help: "ML score cache hits.",
	})

	circuitBreakerState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "shadow_circuit_breaker_state",
		Help: "Circuit breaker state: 0=closed, 1=open, 2=half-open.",
	}, []string{"name"})

	batchSizeHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "shadow_batch_size",
		Help:    "Number of packets per flush batch.",
		Buckets: []float64{10, 25, 50, 100, 200, 500, 1000, 2000},
	})

	criticalAlertsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_critical_alerts_total",
		Help: "Total critical anomaly alerts fired.",
	})

	dlqPublishTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_dlq_publish_total",
		Help: "Total packets sent to Dead Letter Queue.",
	})

	rateLimitedPackets = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_rate_limited_packets_total",
		Help: "Packets dropped due to rate limiting.",
	})

	adsbMessages = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_adsb_messages_total",
		Help: "Total number of ADS‑B messages processed.",
	})
	emergencySquawk = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_emergency_squawk_total",
		Help: "Number of emergency squawk codes detected (7700, 7600, 7500).",
	})
)

// ----------------------------------------------------------------------------
// Circuit Breaker
// ----------------------------------------------------------------------------
type MLCircuitBreaker struct {
	cb     *gobreaker.CircuitBreaker
	client *ml.MLClient
	name   string
}

var ErrMLUnavailable = errors.New("ML service unavailable (circuit open)")

func newMLCircuitBreaker(client *ml.MLClient, cfg Config) *MLCircuitBreaker {
	settings := gobreaker.Settings{
		Name:        "shadow-ml",
		MaxRequests: cfg.CircuitBreaker.MaxRequests,
		Interval:    cfg.CircuitBreaker.Interval,
		Timeout:     cfg.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			if counts.Requests < 5 {
				return false
			}
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return failureRatio >= cfg.CircuitBreaker.FailureRatio
		},
		OnStateChange: func(name string, from, to gobreaker.State) {
			log.Warn().Str("breaker", name).Str("from", from.String()).Str("to", to.String()).Msg("Circuit breaker state changed")
			stateVal := map[gobreaker.State]float64{
				gobreaker.StateClosed:   0,
				gobreaker.StateOpen:     1,
				gobreaker.StateHalfOpen: 2,
			}[to]
			circuitBreakerState.WithLabelValues(name).Set(stateVal)
		},
	}
	return &MLCircuitBreaker{
		cb:     gobreaker.NewCircuitBreaker(settings),
		client: client,
		name:   "shadow-ml",
	}
}

func (m *MLCircuitBreaker) Analyze(ctx context.Context, req ml.AnalyzeRequest) (*ml.AnalyzeResponse, error) {
	result, err := m.cb.Execute(func() (interface{}, error) {
		return m.client.AnalyzeWithContext(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	return result.(*ml.AnalyzeResponse), nil
}

func (m *MLCircuitBreaker) UpdateOnline(ctx context.Context, req ml.UpdateRequest) {
	go func() {
		if _, err := m.cb.Execute(func() (interface{}, error) {
			return nil, m.client.UpdateWithContext(ctx, req)
		}); err != nil {
			log.Debug().Err(err).Msg("Online ML update failed (non-critical)")
		}
	}()
}

func (m *MLCircuitBreaker) Explain(ctx context.Context, features []float64) (*ml.ExplainResponse, error) {
	result, err := m.cb.Execute(func() (interface{}, error) {
		return m.client.ExplainWithContext(ctx, features)
	})
	if err != nil {
		return nil, err
	}
	return result.(*ml.ExplainResponse), nil
}

// ----------------------------------------------------------------------------
// Retry, Panic, RateLimiter
// ----------------------------------------------------------------------------
func withRetry(ctx context.Context, maxRetries int, baseDelay time.Duration, operation string, fn func() error) error {
	var err error
	delay := baseDelay
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				delay = time.Duration(float64(delay) * 2)
				if delay > 2*time.Second {
					delay = 2 * time.Second
				}
			}
			log.Debug().Int("attempt", attempt).Dur("delay", delay).Msg("Retrying")
		}
		err = fn()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("operation %s failed after %d attempts: %w", operation, maxRetries+1, err)
}

func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error().
					Str("goroutine", name).
					Interface("panic", r).
					Str("stack", string(debug.Stack())).
					Msg("Recovered from panic")
				packetsProcessed.WithLabelValues("panic").Inc()
			}
		}()
		fn()
	}()
}

type RateLimiter struct {
	mu    sync.RWMutex
	limit int
	win   time.Duration
	count map[string][]time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit: limit,
		win:   window,
		count: make(map[string][]time.Time),
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	times := rl.count[ip]
	cutoff := now.Add(-rl.win)
	keep := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[keep] = t
			keep++
		}
	}
	times = times[:keep]
	if len(times) >= rl.limit {
		return false
	}
	rl.count[ip] = append(times, now)
	return true
}

// ----------------------------------------------------------------------------
// Threat Intelligence Cache
// ----------------------------------------------------------------------------
type ThreatIntelCache struct {
	mu          sync.RWMutex
	ips         map[string]ThreatEntry
	lastRefresh time.Time
}

type ThreatEntry struct {
	Score  float64
	Type   string
	Source string
}

var globalThreatIntel = &ThreatIntelCache{
	ips: map[string]ThreatEntry{
		"185.220.101.5": {Score: 0.95, Type: "tor_exit", Source: "torproject"},
		"198.51.100.42": {Score: 0.80, Type: "c2", Source: "MISP"},
	},
}

func (t *ThreatIntelCache) Lookup(ip string) (ThreatEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.ips[ip]
	return e, ok
}

func (t *ThreatIntelCache) Refresh(ctx context.Context, feedURL string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastRefresh = time.Now()
}

// ----------------------------------------------------------------------------
// SOAR Alert
// ----------------------------------------------------------------------------
type SOARAlert struct {
	Timestamp   time.Time              `json:"timestamp"`
	SrcIP       string                 `json:"src_ip"`
	DstIP       string                 `json:"dst_ip"`
	Score       float64                `json:"score"`
	Explanation []ml.FeatureImportance `json:"explanation,omitempty"`
	AttackTypes []string               `json:"attack_types"`
	Severity    string                 `json:"severity"`
}

func fireCriticalAlert(ctx context.Context, alert SOARAlert, webhookURL string) {
	if webhookURL == "" {
		return
	}
	safeGo("soar-alert", func() {
		body, err := json.Marshal(alert)
		if err != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Warn().Err(err).Msg("SOAR alert delivery failed")
			return
		}
		defer resp.Body.Close()
		criticalAlertsTotal.Inc()
		log.Info().
			Str("src_ip", alert.SrcIP).
			Float64("score", alert.Score).
			Str("severity", alert.Severity).
			Msg("Critical alert fired to SOAR")
	})
}

// ----------------------------------------------------------------------------
// Fallback Score (Aviation‑only)
// ----------------------------------------------------------------------------
func fallbackScore(p models.ParsedPacket) float64 {
	weights := struct {
		critical    float64
		largePacket float64
		attackTypes float64
		portScan    float64
		aviation    float64
	}{0.40, 0.15, 0.30, 0.10, 0.20}

	score := 0.0
	if p.IsCritical {
		score += weights.critical
	}
	if p.Size > 1400 {
		score += weights.largePacket
	}
	if len(p.AttackTypes) > 0 {
		score += weights.attackTypes * math.Min(float64(len(p.AttackTypes))/3.0, 1.0)
	}
	if p.DstPort > 49000 && p.DstPort < 65000 {
		score += weights.portScan * 0.5
	}
	if p.Squawk != nil && (*p.Squawk == 7700 || *p.Squawk == 7600 || *p.Squawk == 7500) {
		score += weights.aviation
	}
	return 1.0 / (1.0 + math.Exp(-6.0*(score-0.5)))
}

// ----------------------------------------------------------------------------
// Health Checks
// ----------------------------------------------------------------------------
type HealthStatus struct {
	Status    string                 `json:"status"`
	Checks    map[string]CheckResult `json:"checks"`
	Timestamp time.Time              `json:"timestamp"`
	Version   string                 `json:"version"`
}

type CheckResult struct {
	Status  string `json:"status"`
	Latency string `json:"latency,omitempty"`
	Error   string `json:"error,omitempty"`
}

func newHealthHandler(ch *storage.ClickHouseClient, pg *storage.PostgresClient,
	redis *storage.RedisClient, cb *MLCircuitBreaker) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		checks := map[string]CheckResult{}
		overall := "ok"

		t0 := time.Now()
		if err := ch.Ping(ctx); err != nil {
			checks["clickhouse"] = CheckResult{Status: "down", Error: err.Error()}
			overall = "degraded"
		} else {
			checks["clickhouse"] = CheckResult{Status: "ok", Latency: time.Since(t0).String()}
		}

		t0 = time.Now()
		if err := pg.Ping(ctx); err != nil {
			checks["postgres"] = CheckResult{Status: "down", Error: err.Error()}
			overall = "degraded"
		} else {
			checks["postgres"] = CheckResult{Status: "ok", Latency: time.Since(t0).String()}
		}

		t0 = time.Now()
		if err := redis.Ping(ctx); err != nil {
			checks["redis"] = CheckResult{Status: "down", Error: err.Error()}
			overall = "degraded"
		} else {
			checks["redis"] = CheckResult{Status: "ok", Latency: time.Since(t0).String()}
		}

		cbState := cb.cb.State()
		if cbState == gobreaker.StateOpen {
			checks["ml"] = CheckResult{Status: "degraded", Error: "circuit open"}
			if overall == "ok" {
				overall = "degraded"
			}
		} else {
			checks["ml"] = CheckResult{Status: "ok"}
		}

		status := HealthStatus{
			Status:    overall,
			Checks:    checks,
			Timestamp: time.Now(),
			Version:   Version,
		}
		w.Header().Set("Content-Type", "application/json")
		if overall == "down" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(status)
	}
}

// ----------------------------------------------------------------------------
// Feature Extraction (Aviation‑only)
// ----------------------------------------------------------------------------
func extractFeatures(p models.ParsedPacket, history []models.ParsedPacket) ml.AnalyzeRequest {
	n := len(history)
	var pktRate, byteRate, avgSize, stdSize float64
	if n > 1 {
		first := history[0].Timestamp
		last := history[n-1].Timestamp
		dur := last.Sub(first).Seconds()
		if dur > 0 {
			var totalBytes int
			for _, h := range history {
				totalBytes += int(h.Size)
			}
			pktRate = float64(n) / dur
			byteRate = float64(totalBytes) / dur
			avgSize = float64(totalBytes) / float64(n)
		}
	}
	if n > 1 {
		mean := avgSize
		var variance float64
		for _, h := range history {
			diff := float64(h.Size) - mean
			variance += diff * diff
		}
		stdSize = math.Sqrt(variance / float64(n))
	}
	iat := 0.0
	if n >= 1 {
		iat = time.Since(history[n-1].Timestamp).Seconds()
	}
	lag1, lag2, lag3 := 0.0, 0.0, 0.0
	if n >= 1 {
		lag1 = float64(history[n-1].Size) / 1500.0
	}
	if n >= 2 {
		lag2 = float64(history[n-2].Size) / 1500.0
	}
	if n >= 3 {
		lag3 = float64(history[n-3].Size) / 1500.0
	}
	burstiness := 0.0
	if avgSize+stdSize > 0 {
		burstiness = (stdSize - avgSize) / (stdSize + avgSize)
	}
	dstSet := map[string]struct{}{}
	portSet := map[int]struct{}{}
	for _, h := range history {
		dstSet[h.DstIP] = struct{}{}
		portSet[int(h.DstPort)] = struct{}{}
	}
	uniqDst := math.Min(float64(len(dstSet))/256.0, 1.0)
	uniqPort := math.Min(float64(len(portSet))/1024.0, 1.0)
	now := time.Now()
	hourSin := math.Sin(2 * math.Pi * float64(now.Hour()) / 24)
	hourCos := math.Cos(2 * math.Pi * float64(now.Hour()) / 24)
	daySin := math.Sin(2 * math.Pi * float64(now.Weekday()) / 7)
	dayCos := math.Cos(2 * math.Pi * float64(now.Weekday()) / 7)
	isTCP := b2f(p.Proto == 6)
	isUDP := b2f(p.Proto == 17)
	isICMP := b2f(p.Proto == 1)
	isWellKnown := b2f(p.DstPort < 1024)
	isEphemeral := b2f(p.DstPort >= 49152)
	szRateInter := (float64(p.Size) / 1500.0) * math.Min(pktRate/1000.0, 1.0)
	synDstInter := isTCP * uniqDst
	attackRatio := math.Min(float64(len(p.AttackTypes))/10.0, 1.0)
	hasCritical := b2f(p.IsCritical)

	// Aviation features
	var altitudeRate, velocityDeviation, altitude, velocity float64
	if p.Altitude != nil {
		altitude = float64(*p.Altitude)
	}
	if p.Velocity != nil {
		velocity = float64(*p.Velocity)
	}
	if len(history) > 0 {
		prev := history[len(history)-1]
		if prev.Altitude != nil && p.Altitude != nil {
			dt := p.Timestamp.Sub(prev.Timestamp).Seconds()
			if dt > 0 {
				altitudeRate = (float64(*p.Altitude) - float64(*prev.Altitude)) / dt
			}
		}
		if prev.Velocity != nil && p.Velocity != nil {
			velocityDeviation = math.Abs(float64(*p.Velocity) - float64(*prev.Velocity))
		}
	}
	squawkAnomaly := 0.0
	if p.Squawk != nil {
		for _, em := range []uint16{7700, 7600, 7500} {
			if *p.Squawk == em {
				squawkAnomaly = 1.0
				emergencySquawk.Inc()
				break
			}
		}
	}
	icaoPresent := 0.0
	if p.ICAO24 != nil && *p.ICAO24 != "" {
		icaoPresent = 1.0
	}

	return ml.AnalyzeRequest{
		Size:              float64(p.Size) / 1500.0,
		AvgSize:           avgSize / 1500.0,
		StdSize:           stdSize / 1500.0,
		TTL:               0.5,
		IsTCP:             isTCP > 0.5,
		IsUDP:             isUDP > 0.5,
		IsICMP:            isICMP > 0.5,
		PacketRate:        math.Min(pktRate/1000.0, 1.0),
		ByteRate:          math.Min(byteRate/1e8, 1.0),
		IAT:               math.Min(iat/60.0, 1.0),
		UniqDst:           uniqDst,
		UniqPort:          uniqPort,
		Burstiness:        burstiness,
		AttackCount:       attackRatio,
		IsCritical:        hasCritical > 0.5,
		Lag1:              lag1,
		Lag2:              lag2,
		Lag3:              lag3,
		HourSin:           hourSin,
		HourCos:           hourCos,
		DaySin:            daySin,
		DayCos:            dayCos,
		IsWellKnown:       isWellKnown > 0.5,
		IsEphemeral:       isEphemeral > 0.5,
		SzRateInter:       szRateInter,
		SynDstInter:       synDstInter,
		Altitude:          altitude,
		Velocity:          velocity,
		AltitudeRate:      altitudeRate,
		VelocityDeviation: velocityDeviation,
		SquawkAnomaly:     squawkAnomaly,
		ICAOPresent:       icaoPresent,
	}
}

func b2f(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// ----------------------------------------------------------------------------
// Enricher (Aviation‑only)
// ----------------------------------------------------------------------------
func enrichPacket(ctx context.Context, p *models.ParsedPacket,
	threatIntel *ThreatIntelCache, redis *storage.RedisClient,
	rateLimiter *RateLimiter, cfg Config) {

	p.OrgID = "default"

	// Threat intelligence
	if entry, ok := threatIntel.Lookup(p.SrcIP); ok {
		p.ThreatScore = entry.Score
		p.ThreatType = entry.Type
		p.ThreatSource = entry.Source
	} else if entry, ok := threatIntel.Lookup(p.DstIP); ok {
		p.ThreatScore = entry.Score * 0.8
		p.ThreatType = entry.Type
		p.ThreatSource = entry.Source
	}

	// Aviation enrichment: fetch aircraft details from Redis
	if p.ICAO24 != nil && *p.ICAO24 != "" {
		var aircraft struct {
			Registration string `json:"registration"`
			Type         string `json:"type"`
			Operator     string `json:"operator"`
		}
		if err := redis.GetAircraft(ctx, *p.ICAO24, &aircraft); err == nil {
			if aircraft.Type != "" {
				p.AircraftType = &aircraft.Type
			}
			if aircraft.Operator != "" {
				p.Tags = append(p.Tags, "operator:"+aircraft.Operator)
			}
		}
	}

	// Rate limiting per aircraft (ICAO24) or IP
	rateKey := p.SrcIP
	if p.ICAO24 != nil && *p.ICAO24 != "" {
		rateKey = *p.ICAO24
	}
	if !rateLimiter.Allow(rateKey) {
		rateLimitedPackets.Inc()
		p.RateAnomaly = true
	}
}

// ----------------------------------------------------------------------------
// ProcessorState and methods
// ----------------------------------------------------------------------------
type ProcessorState struct {
	cfg         *Config
	ch          *storage.ClickHouseClient
	pg          *storage.PostgresClient
	redis       *storage.RedisClient
	mlCB        *MLCircuitBreaker
	threatIntel *ThreatIntelCache
	dlq         *kafka.Producer
	rateLimiter *RateLimiter
	batchMu     sync.Mutex
	batch       []models.ParsedPacket
	flushCh     chan struct{}
	wg          sync.WaitGroup
	inFlight    int64
}

func (ps *ProcessorState) scoreWithCache(ctx context.Context,
	p models.ParsedPacket, req ml.AnalyzeRequest) (float64, []ml.FeatureImportance, error) {

	cacheKey := fmt.Sprintf("mlcache:%s:%s:%d:%d", p.SrcIP, p.DstIP, p.Size, p.Proto)
	if cached, err := ps.redis.Get(ctx, cacheKey); err == nil {
		var resp ml.AnalyzeResponse
		if json.Unmarshal([]byte(cached), &resp) == nil {
			mlCacheHits.Inc()
			return resp.Score, resp.TopFeatures, nil
		}
	}
	result, err := ps.mlCB.Analyze(ctx, req)
	if err != nil {
		return 0, nil, err
	}
	var explanation []ml.FeatureImportance
	if result.Score > ps.cfg.ML.ExplainThreshold {
		if exp, expErr := ps.mlCB.Explain(ctx, req.ToSlice()); expErr == nil {
			explanation = exp.FeatureImportances
		}
	}
	if payload, err := json.Marshal(result); err == nil {
		ps.redis.Set(ctx, cacheKey, string(payload), ps.cfg.ML.CacheTTL)
	}
	return result.Score, explanation, nil
}

func (ps *ProcessorState) loadIPHistory(ctx context.Context,
	srcIP string) ([]models.ParsedPacket, error) {
	key := fmt.Sprintf("history:%s", srcIP)
	raw, err := ps.redis.LRange(ctx, key, -20, -1)
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	history := make([]models.ParsedPacket, 0, len(raw))
	for _, r := range raw {
		var p models.ParsedPacket
		if json.Unmarshal([]byte(r), &p) == nil {
			history = append(history, p)
		}
	}
	return history, nil
}

func (ps *ProcessorState) saveIPHistory(ctx context.Context, p models.ParsedPacket) {
	safeGo("save-history", func() {
		key := fmt.Sprintf("history:%s", p.SrcIP)
		payload, err := json.Marshal(p)
		if err != nil {
			return
		}
		pipe := ps.redis.Pipeline()
		pipe.RPush(context.Background(), key, string(payload))
		pipe.LTrim(context.Background(), key, -50, -1)
		pipe.Expire(context.Background(), key, 10*time.Minute)
		_, _ = pipe.Exec(context.Background())
	})
}

func (ps *ProcessorState) flushBatch(ctx context.Context) {
	ps.batchMu.Lock()
	if len(ps.batch) == 0 {
		ps.batchMu.Unlock()
		return
	}
	toWrite := make([]models.ParsedPacket, len(ps.batch))
	copy(toWrite, ps.batch)
	ps.batch = ps.batch[:0]
	ps.batchMu.Unlock()

	batchSizeHistogram.Observe(float64(len(toWrite)))
	atomic.AddInt64(&ps.inFlight, 1)
	defer atomic.AddInt64(&ps.inFlight, -1)

	ps.wg.Add(1)
	safeGo("flush-batch", func() {
		defer ps.wg.Done()
		t0 := time.Now()
		var wg2 sync.WaitGroup
		wg2.Add(2)

		go func() {
			defer wg2.Done()
			err := withRetry(ctx, ps.cfg.Kafka.MaxRetries, ps.cfg.Kafka.RetryBaseDelay,
				"clickhouse-insert", func() error {
					return ps.ch.InsertBatch(ctx, toWrite)
				})
			if err != nil {
				log.Error().Err(err).Int("count", len(toWrite)).Msg("ClickHouse batch failed")
				ps.sendToDLQ(ctx, toWrite)
			}
		}()
		go func() {
			defer wg2.Done()
			err := withRetry(ctx, ps.cfg.Kafka.MaxRetries, ps.cfg.Kafka.RetryBaseDelay,
				"postgres-upsert", func() error {
					return ps.pg.UpsertBatch(ctx, toWrite)
				})
			if err != nil {
				log.Error().Err(err).Int("count", len(toWrite)).Msg("PostgreSQL batch failed")
			}
		}()
		wg2.Wait()
		processingLatency.WithLabelValues("batch_write").Observe(time.Since(t0).Seconds())
		log.Debug().Int("count", len(toWrite)).Dur("took", time.Since(t0)).Msg("Batch flushed")
	})
}

func (ps *ProcessorState) sendToDLQ(ctx context.Context, packets []models.ParsedPacket) {
	for _, p := range packets {
		payload, _ := json.Marshal(p)
		// שינוי מ-Publish ל-Send
		if err := ps.dlq.Send(ctx, ps.cfg.Kafka.DLQTopic, "", payload); err != nil {
			log.Error().Err(err).Str("src", p.SrcIP).Msg("DLQ publish failed")
		} else {
			dlqPublishTotal.Inc()
		}
	}
	packetsProcessed.WithLabelValues("dlq").Add(float64(len(packets)))
}

func (ps *ProcessorState) Flush(ctx context.Context) error {
	ps.batchMu.Lock()
	if len(ps.batch) == 0 {
		ps.batchMu.Unlock()
		return nil
	}
	toWrite := make([]models.ParsedPacket, len(ps.batch))
	copy(toWrite, ps.batch)
	ps.batch = ps.batch[:0]
	ps.batchMu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	var chErr, pgErr error
	go func() {
		defer wg.Done()
		chErr = withRetry(ctx, ps.cfg.Kafka.MaxRetries, ps.cfg.Kafka.RetryBaseDelay,
			"clickhouse-insert-final", func() error {
				return ps.ch.InsertBatch(ctx, toWrite)
			})
	}()
	go func() {
		defer wg.Done()
		pgErr = withRetry(ctx, ps.cfg.Kafka.MaxRetries, ps.cfg.Kafka.RetryBaseDelay,
			"postgres-upsert-final", func() error {
				return ps.pg.UpsertBatch(ctx, toWrite)
			})
	}()
	wg.Wait()
	if chErr != nil || pgErr != nil {
		ps.sendToDLQ(ctx, toWrite)
		return fmt.Errorf("final flush failed: ch=%v, pg=%v", chErr, pgErr)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Packet processing
// ----------------------------------------------------------------------------
func (ps *ProcessorState) processPacket(ctx context.Context, data []byte) error {
	start := time.Now()
	defer func() {
		processingLatency.WithLabelValues("total").Observe(time.Since(start).Seconds())
	}()

	t0 := time.Now()
	var packet models.ParsedPacket
	if err := json.Unmarshal(data, &packet); err != nil {
		packetsProcessed.WithLabelValues("parse_error").Inc()
		return fmt.Errorf("unmarshal: %w", err)
	}

	parsed, err := parser.Parse(data, int(packet.DstPort))
	if err == nil && parsed != nil {
		packet.Protocol = parsed.Protocol
		packet.ParsedData = parsed.ParsedData

		switch parsed.Protocol {
		case "adsb":
			adsbMessages.Inc()
			if v, ok := parsed.ParsedData["icao24"].(string); ok {
				packet.ICAO24 = &v
			}
			if v, ok := parsed.ParsedData["callsign"].(string); ok {
				packet.Callsign = &v
			}
			if v, ok := parsed.ParsedData["flight_number"].(string); ok {
				packet.FlightNumber = &v
			}
			if v, ok := parsed.ParsedData["latitude"].(float64); ok {
				packet.Latitude = &v
			}
			if v, ok := parsed.ParsedData["longitude"].(float64); ok {
				packet.Longitude = &v
			}
			if v, ok := parsed.ParsedData["altitude"].(float32); ok {
				packet.Altitude = &v
			}
			if v, ok := parsed.ParsedData["velocity"].(float32); ok {
				packet.Velocity = &v
			}
			if v, ok := parsed.ParsedData["heading"].(float32); ok {
				packet.Heading = &v
			}
			if v, ok := parsed.ParsedData["vertical_rate"].(float32); ok {
				packet.VerticalRate = &v
			}
			if v, ok := parsed.ParsedData["squawk"].(uint16); ok {
				packet.Squawk = &v
			}
		case "acars":
			if v, ok := parsed.ParsedData["mode"].(string); ok {
				packet.ACARSMode = &v
			}
			if v, ok := parsed.ParsedData["text"].(string); ok {
				packet.ACARSText = &v
			}
			if v, ok := parsed.ParsedData["aircraft"].(string); ok {
				packet.ACARSAircraft = &v
			}
		case "arinc429":
			packet.AvionicsBus = "arinc429"
			if v, ok := parsed.ParsedData["label"].(uint8); ok {
				packet.BusLabel = &v
			}
			if v, ok := parsed.ParsedData["sdi"].(uint8); ok {
				packet.BusSDI = &v
			}
			if v, ok := parsed.ParsedData["data"].(uint32); ok {
				packet.BusData = &v
			}
			if v, ok := parsed.ParsedData["ssm"].(uint8); ok {
				packet.BusSSM = &v
			}
		case "afdx":
			packet.AvionicsBus = "afdx"
		}
	}
	processingLatency.WithLabelValues("parse").Observe(time.Since(t0).Seconds())

	t0 = time.Now()
	enrichPacket(ctx, &packet, ps.threatIntel, ps.redis, ps.rateLimiter, *ps.cfg)
	processingLatency.WithLabelValues("enrich").Observe(time.Since(t0).Seconds())

	history, err := ps.loadIPHistory(ctx, packet.SrcIP)
	if err != nil {
		log.Debug().Err(err).Str("src", packet.SrcIP).Msg("History load failed (non-critical)")
	}

	features := extractFeatures(packet, history)

	t0 = time.Now()
	score, explanation, err := ps.scoreWithCache(ctx, packet, features)
	if err != nil {
		score = fallbackScore(packet)
		log.Debug().Err(err).Float64("fallback_score", score).Msg("ML unavailable, using fallback")
	}
	packet.Score = score
	mlScoreHistogram.Observe(score)
	processingLatency.WithLabelValues("ml").Observe(time.Since(t0).Seconds())

	if ps.cfg.ML.UpdateEnabled {
		ps.mlCB.UpdateOnline(ctx, ml.UpdateRequest{
			Features: features.ToSlice(),
			Score:    score,
			Label:    1,
		})
	}

	ps.saveIPHistory(ctx, packet)

	safeGo("redis-cache", func() {
		key := fmt.Sprintf("packet:%s:%d", packet.SrcIP, packet.Timestamp.UnixMilli())
		payload, _ := json.Marshal(packet)
		ps.redis.Set(context.Background(), key, payload, ps.cfg.Processor.RedisTTL)
	})

	alertScore := score
	if packet.Squawk != nil {
		for _, em := range ps.cfg.Aviation.EmergencySquawk {
			if *packet.Squawk == em {
				alertScore = 1.0
				break
			}
		}
	}
	if alertScore > ps.cfg.Alerting.CriticalThreshold {
		severity := "high"
		if alertScore > 0.95 {
			severity = "critical"
		}
		fireCriticalAlert(ctx, SOARAlert{
			Timestamp:   packet.Timestamp,
			SrcIP:       packet.SrcIP,
			DstIP:       packet.DstIP,
			Score:       alertScore,
			Explanation: explanation,
			AttackTypes: packet.AttackTypes,
			Severity:    severity,
		}, ps.cfg.Alerting.SOARWebhook)
	}

	ps.batchMu.Lock()
	ps.batch = append(ps.batch, packet)
	shouldFlush := len(ps.batch) >= ps.cfg.Processor.BatchSize
	overloaded := len(ps.batch) >= ps.cfg.Processor.MaxBatchSize
	ps.batchMu.Unlock()
	if shouldFlush {
		select {
		case ps.flushCh <- struct{}{}:
		default:
		}
	}
	if overloaded {
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
		}
		log.Warn().Int("batch_size", len(ps.batch)).Msg("Backpressure: consumer paused")
	}
	packetsProcessed.WithLabelValues("success").Inc()
	log.Debug().
		Str("src", packet.SrcIP).
		Str("dst", packet.DstIP).
		Float64("score", score).
		Bool("critical", alertScore > ps.cfg.Alerting.CriticalThreshold).
		Msg("Packet processed")
	return nil
}

// ----------------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------------
func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs

	cfg := loadConfig()
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	if cfg.Environment != "production" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	log.Info().
		Str("version", Version).
		Str("build_time", BuildTime).
		Str("git_commit", GitCommit).
		Str("env", cfg.Environment).
		Msg("Starting Shadow NDR Ingestion Service")

	if cfg.Tracing.Enabled {
		tp := trace.NewNoopTracerProvider()
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
		log.Info().Str("endpoint", cfg.Tracing.Endpoint).Msg("Tracing enabled")
	}

	ch, err := storage.NewClickHouse(cfg.ClickHouse.Host, cfg.ClickHouse.Port,
		cfg.ClickHouse.Database, cfg.ClickHouse.User, cfg.ClickHouse.Password)
	if err != nil {
		log.Fatal().Err(err).Msg("ClickHouse init failed")
	}
	defer ch.Close()

	pg, err := storage.NewPostgres(cfg.Postgres.Host, cfg.Postgres.Port,
		cfg.Postgres.Database, cfg.Postgres.User, cfg.Postgres.Password)
	if err != nil {
		log.Fatal().Err(err).Msg("PostgreSQL init failed")
	}
	defer pg.Close()

	redis, err := storage.NewRedis(cfg.Redis.Host, cfg.Redis.Port,
		cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		log.Fatal().Err(err).Msg("Redis init failed")
	}
	defer redis.Close()

	mlClient := ml.NewClient(cfg.ML.URL, cfg.ML.Timeout)
	mlCB := newMLCircuitBreaker(mlClient, *cfg)

	// תיקון: יצירת producer עם Config מלא
	producerCfg := &kafka.Config{
		Brokers: cfg.Kafka.Brokers,
	}
	dlqProducer, err := kafka.NewProducer(producerCfg, cfg.Kafka.DLQTopic)
	if err != nil {
		log.Fatal().Err(err).Msg("DLQ producer init failed")
	}
	defer dlqProducer.Close()

	rateLimiter := NewRateLimiter(1000, cfg.Processor.RateLimitInterval)

	ctx, cancel := context.WithCancel(context.Background())
	safeGo("threat-intel-refresh", func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				globalThreatIntel.Refresh(ctx, "")
			case <-ctx.Done():
				return
			}
		}
	})

	ps := &ProcessorState{
		cfg:         cfg,
		ch:          ch,
		pg:          pg,
		redis:       redis,
		mlCB:        mlCB,
		threatIntel: globalThreatIntel,
		dlq:         dlqProducer,
		rateLimiter: rateLimiter,
		batch:       make([]models.ParsedPacket, 0, cfg.Processor.BatchSize),
		flushCh:     make(chan struct{}, 4),
	}

	flushTicker := time.NewTicker(cfg.Processor.FlushInterval)
	safeGo("flush-ticker", func() {
		for {
			select {
			case <-flushTicker.C:
				select {
				case ps.flushCh <- struct{}{}:
				default:
				}
			case <-ctx.Done():
				return
			}
		}
	})

	for i := 0; i < cfg.Processor.WorkerCount; i++ {
		idx := i
		safeGo(fmt.Sprintf("flush-worker-%d", idx), func() {
			for {
				select {
				case _, ok := <-ps.flushCh:
					if !ok {
						return
					}
					ps.flushBatch(ctx)
				case <-ctx.Done():
					return
				}
			}
		})
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", newHealthHandler(ch, pg, redis, mlCB))
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ready")
	})
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.MetricsPort),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	safeGo("http-server", func() {
		log.Info().Int("port", cfg.MetricsPort).Msg("HTTP server listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("HTTP server error")
		}
	})

	// תיקון: יצירת consumer עם Config מלא
	consumerCfg := &kafka.Config{
		Brokers: cfg.Kafka.Brokers,
		Consumer: struct {
			GroupID           string        `yaml:"group_id" env:"KAFKA_GROUP_ID"`
			Topics            []string      `yaml:"topics"`
			InitialOffset     string        `yaml:"initial_offset" default:"newest"`
			ProcessingTimeout time.Duration `yaml:"processing_timeout" default:"30s"`
			Workers           int           `yaml:"workers" default:"1"`
			SessionTimeout    time.Duration `yaml:"session_timeout" default:"30s"`
			HeartbeatInterval time.Duration `yaml:"heartbeat_interval" default:"3s"`
		}{
			GroupID:           cfg.Kafka.GroupID,
			Topics:            []string{cfg.Kafka.Topic},
			ProcessingTimeout: cfg.Processor.ShutdownTimeout,
			Workers:           cfg.Processor.WorkerCount,
		},
	}

	consumer, err := kafka.NewConsumer(consumerCfg, func(ctx context.Context, msg *sarama.ConsumerMessage) error {
		return ps.processPacket(ctx, msg.Value)
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Kafka consumer init failed")
	}
	defer consumer.Stop() // שימוש ב-Stop במקום Close

	consumer.Start() // שימוש ב-Start במקום Consume

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("Shutdown initiated")
		cancel()
		flushTicker.Stop()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Processor.ShutdownTimeout)
		defer shutdownCancel()

		if err := ps.Flush(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Final flush failed")
		}

		done := make(chan struct{})
		go func() {
			ps.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			log.Info().Msg("All data flushed")
		case <-shutdownCtx.Done():
			log.Warn().Msg("Shutdown timeout: data may be lost")
		}

		httpShutdownCtx, httpCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer httpCancel()
		_ = srv.Shutdown(httpShutdownCtx)

		close(ps.flushCh)
		log.Info().Msg("Service stopped")
		os.Exit(0)
	}()

	log.Info().Str("topic", cfg.Kafka.Topic).Strs("brokers", cfg.Kafka.Brokers).Msg("Kafka consumer started")
}
