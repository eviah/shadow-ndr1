package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

var (
	producedMessages = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kafka_produced_messages_total",
		Help: "Total number of produced messages",
	}, []string{"topic", "status"})
	produceErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kafka_produce_errors_total",
		Help: "Total number of produce errors",
	}, []string{"topic"})
	produceLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "kafka_produce_latency_seconds",
		Help:    "Produce latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"topic"})
)

// Producer handles asynchronous Kafka message production with idempotence and transactions.
type Producer struct {
	asyncProducer sarama.AsyncProducer
	syncProducer  sarama.SyncProducer // optional for transactional
	config        *Config
	topic         string
	mu            sync.RWMutex
	closed        bool
	closeCh       chan struct{}
	wg            sync.WaitGroup
	errorsCh      chan error
	successCh     chan *sarama.ProducerMessage
}

// NewProducer creates a new Kafka producer.
func NewProducer(cfg *Config, defaultTopic string) (*Producer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	saramaCfg, err := cfg.NewSaramaConfig()
	if err != nil {
		return nil, err
	}

	asyncProducer, err := sarama.NewAsyncProducer(cfg.Brokers, saramaCfg)
	if err != nil {
		return nil, err
	}

	p := &Producer{
		asyncProducer: asyncProducer,
		config:        cfg,
		topic:         defaultTopic,
		closeCh:       make(chan struct{}),
		errorsCh:      make(chan error, 100),
		successCh:     make(chan *sarama.ProducerMessage, 100),
	}

	// Start error and success handlers
	p.wg.Add(1)
	go p.handleErrors()

	p.wg.Add(1)
	go p.handleSuccesses()

	return p, nil
}

// Send sends a message to Kafka (async).
func (p *Producer) Send(ctx context.Context, topic, key string, value interface{}) error {
	start := time.Now()
	data, err := json.Marshal(value)
	if err != nil {
		produceErrors.WithLabelValues(topic).Inc()
		return err
	}

	msg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(data),
	}

	select {
	case p.asyncProducer.Input() <- msg:
		produceLatency.WithLabelValues(topic).Observe(time.Since(start).Seconds())
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.closeCh:
		return ErrProducerClosed
	}
}

// SendSync sends a message synchronously (blocking) with retries.
func (p *Producer) SendSync(ctx context.Context, topic, key string, value interface{}) (*sarama.ProducerMessage, error) {
	if p.syncProducer == nil {
		// Create a sync producer on demand (or use the same async with waiting)
		saramaCfg, err := p.config.NewSaramaConfig()
		if err != nil {
			return nil, err
		}
		saramaCfg.Producer.Return.Successes = true
		syncProducer, err := sarama.NewSyncProducer(p.config.Brokers, saramaCfg)
		if err != nil {
			return nil, err
		}
		p.syncProducer = syncProducer
	}

	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	msg := &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.StringEncoder(key),
		Value: sarama.ByteEncoder(data),
	}

	// Use context with timeout
	done := make(chan struct{})
	var sendErr error

	go func() {
		defer close(done)
		_, _, sendErr = p.syncProducer.SendMessage(msg)
	}()

	select {
	case <-done:
		if sendErr != nil {
			produceErrors.WithLabelValues(topic).Inc()
			return nil, sendErr
		}
		producedMessages.WithLabelValues(topic, "success").Inc()
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Transaction starts a new transaction (only if idempotent producer enabled).
func (p *Producer) Transaction(ctx context.Context) (*Transaction, error) {
	if !p.config.Producer.EnableIdempotence {
		return nil, ErrTransactionNotSupported
	}
	// For simplicity, we rely on async producer's idempotence; transactional API requires a separate producer.
	// This is a placeholder; full transaction support requires a transactional producer.
	return &Transaction{producer: p}, nil
}

type Transaction struct {
	producer *Producer
}

func (t *Transaction) Send(ctx context.Context, topic, key string, value interface{}) error {
	return t.producer.Send(ctx, topic, key, value)
}

func (t *Transaction) Commit(ctx context.Context) error {
	// No-op for now; real implementation would call BeginTransaction/CommitTransaction
	return nil
}

func (t *Transaction) Abort(ctx context.Context) error {
	return nil
}

// Close flushes pending messages and shuts down the producer.
func (p *Producer) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.closeCh)
	p.mu.Unlock()

	p.asyncProducer.AsyncClose()
	p.wg.Wait()

	if p.syncProducer != nil {
		return p.syncProducer.Close()
	}
	return nil
}

// handleErrors processes async producer errors.
func (p *Producer) handleErrors() {
	defer p.wg.Done()
	for {
		select {
		case err := <-p.asyncProducer.Errors():
			if err == nil {
				continue
			}
			log.Error().Err(err.Err).
				Str("topic", err.Msg.Topic).
				Msg("Kafka produce error")
			produceErrors.WithLabelValues(err.Msg.Topic).Inc()
		case <-p.closeCh:
			return
		}
	}
}

// handleSuccesses processes async producer successes.
func (p *Producer) handleSuccesses() {
	defer p.wg.Done()
	for {
		select {
		case msg := <-p.asyncProducer.Successes():
			if msg == nil {
				continue
			}
			producedMessages.WithLabelValues(msg.Topic, "success").Inc()
		case <-p.closeCh:
			return
		}
	}
}

// ErrProducerClosed returned when trying to send on closed producer.
var ErrProducerClosed = errors.New("kafka producer is closed")

// ErrTransactionNotSupported returned when trying to start transaction without idempotence enabled.
var ErrTransactionNotSupported = errors.New("transaction not supported (enable idempotence)")
