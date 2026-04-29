package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

type RedisClient struct {
	client *redis.Client
}

func NewRedis(host string, port int, password string, db int) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		Password:     password,
		DB:           db,
		PoolSize:     20,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}

	log.Info().Msg("Connected to Redis (Aviation Edition)")
	return &RedisClient{client: client}, nil
}

// AircraftCache – store and retrieve aircraft info
func (r *RedisClient) SetAircraft(ctx context.Context, icao24 string, data interface{}, ttl time.Duration) error {
	key := fmt.Sprintf("aircraft:%s", icao24)
	val, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, key, val, ttl).Err()
}

func (r *RedisClient) GetAircraft(ctx context.Context, icao24 string, dest interface{}) error {
	key := fmt.Sprintf("aircraft:%s", icao24)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(val), dest)
}

// FlightPlanCache
func (r *RedisClient) SetFlightPlan(ctx context.Context, callsign string, plan interface{}, ttl time.Duration) error {
	key := fmt.Sprintf("flightplan:%s", callsign)
	val, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	return r.client.Set(ctx, key, val, ttl).Err()
}

func (r *RedisClient) GetFlightPlan(ctx context.Context, callsign string, dest interface{}) error {
	key := fmt.Sprintf("flightplan:%s", callsign)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(val), dest)
}

// Geo operations for aircraft positions (requires Redis 6+)
func (r *RedisClient) GeoAdd(ctx context.Context, key string, longitude, latitude float64, member string) error {
	return r.client.GeoAdd(ctx, key, &redis.GeoLocation{
		Name:      member,
		Longitude: longitude,
		Latitude:  latitude,
	}).Err()
}

func (r *RedisClient) GeoRadius(ctx context.Context, key string, longitude, latitude, radius float64, unit string) ([]redis.GeoLocation, error) {
	return r.client.GeoRadius(ctx, key, longitude, latitude, &redis.GeoRadiusQuery{
		Radius:    radius,
		Unit:      unit,
		WithCoord: true,
		WithDist:  true,
	}).Result()
}

// Rate limiting (sliding window) per aircraft
func (r *RedisClient) RateLimitAircraft(ctx context.Context, icao24 string, limit int, window time.Duration) (bool, error) {
	key := fmt.Sprintf("ratelimit:%s", icao24)
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}
	return incr.Val() <= int64(limit), nil
}

// PubSub for real‑time alerts
func (r *RedisClient) PublishAlert(ctx context.Context, channel string, alert interface{}) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	return r.client.Publish(ctx, channel, data).Err()
}

// Existing methods (Set, Get, Pipeline, LRange, etc.) remain but can be adapted
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}
func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// Raw exposes the underlying go-redis client. Needed by features that
// build their own Pub/Sub subscribers (gossip mesh, honeynet keyspace
// bridge) — those need the actual *redis.Client rather than the small
// wrapper surface this package exposes.
func (r *RedisClient) Raw() *redis.Client {
	return r.client
}
func (r *RedisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}
func (r *RedisClient) Pipeline() redis.Pipeliner {
	return r.client.Pipeline()
}
func (r *RedisClient) LRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	return r.client.LRange(ctx, key, start, stop).Result()
}
