package ml

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// ----------------------------------------------------------------------------
// Prometheus metrics
// ----------------------------------------------------------------------------

var (
	mlRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ml_requests_total",
			Help: "Total number of ML requests",
		},
		[]string{"status"}, // success, error, circuit_open, cache_hit, fallback
	)
	mlRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ml_request_duration_seconds",
			Help:    "Duration of ML requests",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"type"}, // analyze, bulk, explain, update
	)
	mlCircuitOpen = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ml_circuit_open",
			Help: "1 if circuit breaker is open, 0 otherwise",
		},
	)
	mlFallbackUsed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ml_fallback_used_total",
			Help: "Total number of times fallback model was used",
		},
	)
	mlCacheHit = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ml_cache_hit_total",
			Help: "Total number of deduplicated requests",
		},
	)
	mlRateLimited = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "ml_rate_limited_total",
			Help: "Total number of requests dropped due to rate limiting",
		},
	)
)

// ----------------------------------------------------------------------------
// Local fallback model (logistic regression with trained coefficients)
// ----------------------------------------------------------------------------

var fallbackWeights = []float64{
	-2.0, // bias
	1.5,  // size
	0.5,  // is_tcp
	-0.2, // is_udp
	0.8,  // packet_rate
	0.3,  // byte_rate
	0.6,  // avg_size
	1.2,  // attack_count
	2.0,  // is_critical
	0.5,  // altitude (added for aviation)
	0.3,  // velocity
	0.4,  // altitude_rate
	0.2,  // velocity_deviation
	1.5,  // squawk_anomaly
	0.1,  // icao_present
}

func fallbackScore(features AnalyzeRequest) float64 {
	x := []float64{
		1.0, // bias term
		features.Size,
		boolToFloat(features.IsTCP),
		boolToFloat(features.IsUDP),
		features.PacketRate,
		features.ByteRate,
		features.AvgSize,
		features.AttackCount,
		boolToFloat(features.IsCritical),
		// Aviation features
		features.Altitude,
		features.Velocity,
		features.AltitudeRate,
		features.VelocityDeviation,
		features.SquawkAnomaly,
		features.ICAOPresent,
	}
	var sum float64
	for i, w := range fallbackWeights {
		if i < len(x) {
			sum += w * x[i]
		}
	}
	return 1.0 / (1.0 + math.Exp(-sum))
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// ----------------------------------------------------------------------------
// Request deduplication (LRU cache)
// ----------------------------------------------------------------------------

type cacheEntry struct {
	result *AnalyzeResponse
	ts     time.Time
}

type DedupCache struct {
	cache *lru.Cache
	ttl   time.Duration
}

func NewDedupCache(size int, ttl time.Duration) (*DedupCache, error) {
	c, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &DedupCache{cache: c, ttl: ttl}, nil
}

func (dc *DedupCache) Get(key string) (*AnalyzeResponse, bool) {
	if entry, ok := dc.cache.Get(key); ok {
		e := entry.(cacheEntry)
		if time.Since(e.ts) < dc.ttl {
			return e.result, true
		}
		dc.cache.Remove(key)
	}
	return nil, false
}

func (dc *DedupCache) Put(key string, result *AnalyzeResponse) {
	dc.cache.Add(key, cacheEntry{result: result, ts: time.Now()})
}

func hashFeatures(features AnalyzeRequest) string {
	data, _ := json.Marshal(features)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ----------------------------------------------------------------------------
// Adaptive timeout based on EMA
// ----------------------------------------------------------------------------

type AdaptiveTimeout struct {
	mu         sync.RWMutex
	ema        float64 // exponential moving average of latency
	alpha      float64 // smoothing factor (0.1)
	minTimeout time.Duration
	maxTimeout time.Duration
}

func NewAdaptiveTimeout(min, max time.Duration) *AdaptiveTimeout {
	return &AdaptiveTimeout{
		ema:        float64(max) / 2,
		alpha:      0.1,
		minTimeout: min,
		maxTimeout: max,
	}
}

func (at *AdaptiveTimeout) Observe(duration time.Duration) {
	at.mu.Lock()
	defer at.mu.Unlock()
	if at.ema == 0 {
		at.ema = float64(duration)
	} else {
		at.ema = at.alpha*float64(duration) + (1-at.alpha)*at.ema
	}
}

func (at *AdaptiveTimeout) Get() time.Duration {
	at.mu.RLock()
	defer at.mu.RUnlock()
	t := time.Duration(at.ema)
	if t < at.minTimeout {
		t = at.minTimeout
	}
	if t > at.maxTimeout {
		t = at.maxTimeout
	}
	return t
}

// ----------------------------------------------------------------------------
// Circuit Breaker with health check
// ----------------------------------------------------------------------------

type CircuitBreaker struct {
	mu               sync.Mutex
	failureCount     int
	lastFailureTime  time.Time
	state            string // "closed", "open", "half-open"
	threshold        int
	timeout          time.Duration
	halfOpenRequests int
	successCount     int
	requiredSuccess  int
	healthURL        string
	healthClient     *http.Client
	lastHealthOk     bool
}

func NewCircuitBreaker(threshold int, timeout time.Duration, healthURL string) *CircuitBreaker {
	cb := &CircuitBreaker{
		state:           "closed",
		threshold:       threshold,
		timeout:         timeout,
		requiredSuccess: 3,
		healthURL:       healthURL,
		healthClient:    &http.Client{Timeout: 2 * time.Second},
		lastHealthOk:    true,
	}
	go cb.healthCheckLoop()
	return cb
}

func (cb *CircuitBreaker) healthCheckLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		healthy := cb.checkHealth()
		cb.mu.Lock()
		cb.lastHealthOk = healthy
		if healthy && cb.state == "open" && time.Since(cb.lastFailureTime) > cb.timeout {
			cb.state = "half-open"
			cb.halfOpenRequests = 0
			cb.successCount = 0
			mlCircuitOpen.Set(0)
			log.Info().Msg("Circuit breaker reset by health check")
		}
		cb.mu.Unlock()
	}
}

func (cb *CircuitBreaker) checkHealth() bool {
	if cb.healthURL == "" {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", cb.healthURL, nil)
	if err != nil {
		return false
	}
	resp, err := cb.healthClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	switch cb.state {
	case "open":
		if cb.lastHealthOk {
			cb.state = "half-open"
			cb.halfOpenRequests = 0
			cb.successCount = 0
			mlCircuitOpen.Set(0)
		} else if time.Since(cb.lastFailureTime) > cb.timeout {
			cb.state = "half-open"
			cb.halfOpenRequests = 0
			cb.successCount = 0
			mlCircuitOpen.Set(0)
		} else {
			cb.mu.Unlock()
			mlRequestsTotal.WithLabelValues("circuit_open").Inc()
			return fmt.Errorf("circuit breaker is open")
		}
	case "half-open":
		cb.halfOpenRequests++
		if cb.halfOpenRequests > 1 {
			cb.mu.Unlock()
			mlRequestsTotal.WithLabelValues("circuit_open").Inc()
			return fmt.Errorf("circuit breaker is half-open, only one request allowed")
		}
	}
	cb.mu.Unlock()

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err == nil {
		if cb.state == "half-open" {
			cb.successCount++
			if cb.successCount >= cb.requiredSuccess {
				cb.state = "closed"
				cb.failureCount = 0
				mlCircuitOpen.Set(0)
				log.Info().Msg("Circuit breaker closed")
			}
		} else {
			cb.failureCount = 0
		}
		return nil
	}

	// failure
	if cb.state == "closed" {
		cb.failureCount++
		cb.lastFailureTime = time.Now()
		if cb.failureCount >= cb.threshold {
			cb.state = "open"
			mlCircuitOpen.Set(1)
			log.Warn().Msg("Circuit breaker opened")
		}
	} else if cb.state == "half-open" {
		cb.state = "open"
		cb.lastFailureTime = time.Now()
		mlCircuitOpen.Set(1)
		log.Warn().Msg("Circuit breaker opened from half-open")
	}
	return err
}

// ----------------------------------------------------------------------------
// Retry logic with exponential backoff and jitter
// ----------------------------------------------------------------------------

type RetryConfig struct {
	MaxRetries int
	Initial    time.Duration
	Max        time.Duration
	Factor     float64
	Jitter     float64 // e.g., 0.2 for ±20%
}

var defaultRetryConfig = RetryConfig{
	MaxRetries: 3,
	Initial:    100 * time.Millisecond,
	Max:        2 * time.Second,
	Factor:     2.0,
	Jitter:     0.2,
}

func withRetries(ctx context.Context, fn func() error, cfg RetryConfig) error {
	var err error
	delay := cfg.Initial
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				// exponential backoff + jitter
				delay = time.Duration(float64(delay) * cfg.Factor)
				if delay > cfg.Max {
					delay = cfg.Max
				}
				// add jitter
				if cfg.Jitter > 0 {
					jitter := time.Duration(float64(delay) * cfg.Jitter * (2*rand.Float64() - 1))
					delay += jitter
				}
			}
		}
		err = fn()
		if err == nil {
			return nil
		}
		log.Debug().Err(err).Int("attempt", attempt+1).Msg("ML request failed, retrying")
	}
	return err
}

// ----------------------------------------------------------------------------
// Rate limiter (token bucket)
// ----------------------------------------------------------------------------

type RateLimiter struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	rate     float64 // tokens per second
	lastTick time.Time
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	return &RateLimiter{
		tokens:   float64(burst),
		max:      float64(burst),
		rate:     rate,
		lastTick: time.Now(),
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.lastTick).Seconds()
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.max {
		rl.tokens = rl.max
	}
	rl.lastTick = now
	if rl.tokens >= 1 {
		rl.tokens -= 1
		return true
	}
	return false
}

// ----------------------------------------------------------------------------
// ML Client
// ----------------------------------------------------------------------------

type MLClient struct {
	url             string
	client          *http.Client
	circuitBreaker  *CircuitBreaker
	adaptiveTimeout *AdaptiveTimeout
	cache           *DedupCache
	rateLimiter     *RateLimiter
	tracer          trace.Tracer
}

// AnalyzeRequest defines the input features for anomaly detection.
// Includes full aviation feature set.
type AnalyzeRequest struct {
	// Core
	Size         float64 `json:"size"`
	AvgSize      float64 `json:"avg_size"`
	StdSize      float64 `json:"std_size"`
	TTL          float64 `json:"ttl"`
	IsTCP        bool    `json:"is_tcp"`
	IsUDP        bool    `json:"is_udp"`
	IsICMP       bool    `json:"is_icmp"`
	PacketRate   float64 `json:"packet_rate"`
	ByteRate     float64 `json:"byte_rate"`
	IAT          float64 `json:"iat"`
	UniqDst      float64 `json:"uniq_dst"`
	UniqPort     float64 `json:"uniq_port"`
	Burstiness   float64 `json:"burstiness"`
	AttackCount  float64 `json:"attack_count"`
	IsCritical   bool    `json:"is_critical"`
	Lag1         float64 `json:"lag1"`
	Lag2         float64 `json:"lag2"`
	Lag3         float64 `json:"lag3"`
	HourSin      float64 `json:"hour_sin"`
	HourCos      float64 `json:"hour_cos"`
	DaySin       float64 `json:"day_sin"`
	DayCos       float64 `json:"day_cos"`
	IsModbus     bool    `json:"is_modbus"`
	IsDNP3       bool    `json:"is_dnp3"`
	IsIEC104     bool    `json:"is_iec104"`
	IsWellKnown  bool    `json:"is_well_known"`
	IsEphemeral  bool    `json:"is_ephemeral"`
	SzRateInter  float64 `json:"sz_rate_inter"`
	SynDstInter  float64 `json:"syn_dst_inter"`
	PortVar      float64 `json:"port_var"`
	SrcDstRatio  float64 `json:"src_dst_ratio"`
	PktSizeSkew  float64 `json:"pkt_size_skew"`
	ProtoHomogen float64 `json:"proto_homogen"`

	// Aviation fields (NEW)
	Altitude          float64 `json:"altitude"`
	Velocity          float64 `json:"velocity"`
	AltitudeRate      float64 `json:"altitude_rate"`
	VelocityDeviation float64 `json:"velocity_deviation"`
	SquawkAnomaly     float64 `json:"squawk_anomaly"`
	ICAOPresent       float64 `json:"icao_present"`
}

// ToSlice converts the request to a float64 slice for model input.
// Order must match the ML model's expected input order.
func (a *AnalyzeRequest) ToSlice() []float64 {
	return []float64{
		a.Size, a.AvgSize, a.StdSize,
		a.TTL, boolToFloat(a.IsTCP), boolToFloat(a.IsUDP), boolToFloat(a.IsICMP),
		a.PacketRate, a.ByteRate,
		a.IAT, a.UniqDst, a.UniqPort, a.Burstiness,
		a.AttackCount, boolToFloat(a.IsCritical),
		a.Lag1, a.Lag2, a.Lag3,
		a.HourSin, a.HourCos, a.DaySin, a.DayCos,
		boolToFloat(a.IsModbus), boolToFloat(a.IsDNP3), boolToFloat(a.IsIEC104),
		boolToFloat(a.IsWellKnown), boolToFloat(a.IsEphemeral),
		a.SzRateInter, a.SynDstInter,
		// Aviation features
		a.Altitude, a.Velocity, a.AltitudeRate, a.VelocityDeviation,
		a.SquawkAnomaly, a.ICAOPresent,
	}
}

// AnalyzeResponse defines the result of a prediction.
type AnalyzeResponse struct {
	Score       float64             `json:"score"`
	IsAnomaly   bool                `json:"is_anomaly"`
	Threshold   float64             `json:"threshold"`
	Timestamp   time.Time           `json:"timestamp"`
	TopFeatures []FeatureImportance `json:"top_features,omitempty"`
}

// FeatureImportance describes a feature's contribution.
type FeatureImportance struct {
	Index       int     `json:"index"`
	FeatureName string  `json:"feature_name"`
	Importance  float64 `json:"importance"`
	Value       float64 `json:"value"`
}

// BulkRequest sends multiple feature vectors at once.
type BulkRequest struct {
	Features []AnalyzeRequest `json:"features"`
}

// BulkResponse returns predictions for multiple requests.
type BulkResponse struct {
	Results []AnalyzeResponse `json:"results"`
}

// UpdateRequest sends an online update.
type UpdateRequest struct {
	Features []float64 `json:"features"`
	Score    float64   `json:"score"`
	Label    int       `json:"label"`
}

// ExplainResponse returns feature importances.
type ExplainResponse struct {
	FeatureImportances []FeatureImportance `json:"feature_importances"`
	BaseValue          float64             `json:"base_value"`
	PredictionValue    float64             `json:"prediction_value"`
	Timestamp          time.Time           `json:"timestamp"`
}

// NewMLClient creates a new ML client with all features.
func NewMLClient(url string) *MLClient {
	cache, _ := NewDedupCache(1000, 30*time.Second)
	return &MLClient{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		circuitBreaker:  NewCircuitBreaker(5, 30*time.Second, url+"/health"),
		adaptiveTimeout: NewAdaptiveTimeout(1*time.Second, 10*time.Second),
		cache:           cache,
		rateLimiter:     NewRateLimiter(100, 20), // 100 req/sec, burst 20
		tracer:          otel.Tracer("shadow-ndr/ml-client"),
	}
}

// NewClient creates a client with custom timeout (for backward compatibility).
func NewClient(url string, timeout time.Duration) *MLClient {
	cache, _ := NewDedupCache(1000, 30*time.Second)
	return &MLClient{
		url: url,
		client: &http.Client{
			Timeout: timeout,
		},
		circuitBreaker:  NewCircuitBreaker(5, 30*time.Second, url+"/health"),
		adaptiveTimeout: NewAdaptiveTimeout(timeout/2, timeout),
		cache:           cache,
		rateLimiter:     NewRateLimiter(100, 20),
		tracer:          otel.Tracer("shadow-ndr/ml-client"),
	}
}

// Analyze sends a single feature vector.
func (c *MLClient) Analyze(features AnalyzeRequest) (*AnalyzeResponse, error) {
	return c.AnalyzeWithContext(context.Background(), features)
}

// AnalyzeWithContext sends a request with context (supports tracing).
func (c *MLClient) AnalyzeWithContext(ctx context.Context, features AnalyzeRequest) (*AnalyzeResponse, error) {
	ctx, span := c.tracer.Start(ctx, "ml.Analyze")
	defer span.End()

	// Rate limiting
	if !c.rateLimiter.Allow() {
		mlRateLimited.Inc()
		span.SetStatus(codes.Error, "rate limited")
		return nil, fmt.Errorf("rate limited")
	}

	// Deduplication
	key := hashFeatures(features)
	if result, ok := c.cache.Get(key); ok {
		mlRequestsTotal.WithLabelValues("cache_hit").Inc()
		mlCacheHit.Inc()
		span.SetAttributes(attribute.Bool("cache_hit", true))
		return result, nil
	}

	start := time.Now()
	var result *AnalyzeResponse
	var err error

	err = c.circuitBreaker.Call(func() error {
		timeout := c.adaptiveTimeout.Get()
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		return withRetries(reqCtx, func() error {
			resp, e := c.doRequest(reqCtx, features)
			if e != nil {
				return e
			}
			result = resp
			return nil
		}, defaultRetryConfig)
	})

	duration := time.Since(start)
	c.adaptiveTimeout.Observe(duration)
	mlRequestDuration.WithLabelValues("analyze").Observe(duration.Seconds())

	if err != nil {
		mlRequestsTotal.WithLabelValues("error").Inc()
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		log.Warn().Err(err).Msg("ML request failed, using fallback model")

		// Fallback model
		score := fallbackScore(features)
		mlFallbackUsed.Inc()
		result = &AnalyzeResponse{
			Score:     score,
			IsAnomaly: score > 0.95,
			Threshold: 0.95,
			Timestamp: time.Now(),
		}
		mlRequestsTotal.WithLabelValues("fallback").Inc()
	} else {
		mlRequestsTotal.WithLabelValues("success").Inc()
		c.cache.Put(key, result)
	}

	span.SetAttributes(
		attribute.Float64("score", result.Score),
		attribute.Bool("is_anomaly", result.IsAnomaly),
		attribute.Float64("duration_sec", duration.Seconds()),
	)
	return result, nil
}

// Bulk sends multiple requests in a single call (optimized).
func (c *MLClient) Bulk(ctx context.Context, features []AnalyzeRequest) ([]AnalyzeResponse, error) {
	ctx, span := c.tracer.Start(ctx, "ml.Bulk")
	defer span.End()

	if !c.rateLimiter.Allow() {
		mlRateLimited.Inc()
		return nil, fmt.Errorf("rate limited")
	}

	start := time.Now()
	var results []AnalyzeResponse
	err := c.circuitBreaker.Call(func() error {
		timeout := c.adaptiveTimeout.Get()
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		return withRetries(reqCtx, func() error {
			resp, e := c.doBulkRequest(reqCtx, features)
			if e != nil {
				return e
			}
			results = resp.Results
			return nil
		}, defaultRetryConfig)
	})

	duration := time.Since(start)
	mlRequestDuration.WithLabelValues("bulk").Observe(duration.Seconds())

	if err != nil {
		mlRequestsTotal.WithLabelValues("error").Inc()
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		// fallback per request
		results = make([]AnalyzeResponse, len(features))
		for i, f := range features {
			score := fallbackScore(f)
			results[i] = AnalyzeResponse{
				Score:     score,
				IsAnomaly: score > 0.95,
				Threshold: 0.95,
				Timestamp: time.Now(),
			}
		}
		mlFallbackUsed.Add(float64(len(features)))
		mlRequestsTotal.WithLabelValues("fallback").Add(float64(len(features)))
	} else {
		mlRequestsTotal.WithLabelValues("success").Inc()
	}
	return results, nil
}

// UpdateWithContext sends an online update.
func (c *MLClient) UpdateWithContext(ctx context.Context, req UpdateRequest) error {
	ctx, span := c.tracer.Start(ctx, "ml.Update")
	defer span.End()

	if !c.rateLimiter.Allow() {
		mlRateLimited.Inc()
		return fmt.Errorf("rate limited")
	}

	start := time.Now()
	err := c.circuitBreaker.Call(func() error {
		timeout := c.adaptiveTimeout.Get()
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return withRetries(reqCtx, func() error {
			return c.doUpdateRequest(reqCtx, req)
		}, defaultRetryConfig)
	})
	mlRequestDuration.WithLabelValues("update").Observe(time.Since(start).Seconds())

	if err != nil {
		mlRequestsTotal.WithLabelValues("error").Inc()
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	mlRequestsTotal.WithLabelValues("success").Inc()
	return nil
}

// ExplainWithContext requests feature importance explanation.
func (c *MLClient) ExplainWithContext(ctx context.Context, features []float64) (*ExplainResponse, error) {
	ctx, span := c.tracer.Start(ctx, "ml.Explain")
	defer span.End()

	if !c.rateLimiter.Allow() {
		mlRateLimited.Inc()
		return nil, fmt.Errorf("rate limited")
	}

	start := time.Now()
	var resp *ExplainResponse
	err := c.circuitBreaker.Call(func() error {
		timeout := c.adaptiveTimeout.Get()
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return withRetries(reqCtx, func() error {
			r, e := c.doExplainRequest(reqCtx, features)
			if e != nil {
				return e
			}
			resp = r
			return nil
		}, defaultRetryConfig)
	})
	mlRequestDuration.WithLabelValues("explain").Observe(time.Since(start).Seconds())

	if err != nil {
		mlRequestsTotal.WithLabelValues("error").Inc()
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	mlRequestsTotal.WithLabelValues("success").Inc()
	return resp, nil
}

// --- internal request helpers ---

func (c *MLClient) doRequest(ctx context.Context, features AnalyzeRequest) (*AnalyzeResponse, error) {
	body, err := json.Marshal(features)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.url+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	// propagate trace context
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var reader io.ReadCloser = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(reader)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result AnalyzeResponse
	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *MLClient) doBulkRequest(ctx context.Context, features []AnalyzeRequest) (*BulkResponse, error) {
	body, err := json.Marshal(BulkRequest{Features: features})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.url+"/bulk", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result BulkResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *MLClient) doUpdateRequest(ctx context.Context, req UpdateRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.url+"/update", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(httpReq.Header))

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	return nil
}

func (c *MLClient) doExplainRequest(ctx context.Context, features []float64) (*ExplainResponse, error) {
	body, err := json.Marshal(map[string][]float64{"features": features})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.url+"/explain", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result ExplainResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
