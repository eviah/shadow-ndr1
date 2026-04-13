package kafka

import (
	"context"
	"errors"
	"sync"

	"github.com/IBM/sarama"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

var (
	consumedMessages = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kafka_consumed_messages_total",
		Help: "Total number of consumed messages",
	}, []string{"topic", "partition", "status"})
	consumerErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "kafka_consumer_errors_total",
		Help: "Total consumer errors",
	}, []string{"topic"})
)

type MessageHandler func(ctx context.Context, msg *sarama.ConsumerMessage) error

type Consumer struct {
	consumerGroup sarama.ConsumerGroup
	config        *Config
	handler       MessageHandler
	topics        []string
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	mu            sync.Mutex
	closed        bool
	closeCh       chan struct{}
}

func NewConsumer(cfg *Config, handler MessageHandler) (*Consumer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.Consumer.Topics) == 0 {
		return nil, errors.New("no topics configured")
	}

	saramaCfg, err := cfg.NewSaramaConfig()
	if err != nil {
		return nil, err
	}

	consumerGroup, err := sarama.NewConsumerGroup(cfg.Brokers, cfg.Consumer.GroupID, saramaCfg)
	if err != nil {
		return nil, err
	}

	_, cancel := context.WithCancel(context.Background())

	return &Consumer{
		consumerGroup: consumerGroup,
		config:        cfg,
		handler:       handler,
		topics:        cfg.Consumer.Topics,
		cancel:        cancel,
		closeCh:       make(chan struct{}),
	}, nil
}

func (c *Consumer) Start() {
	c.wg.Add(1)
	go c.run()
}

func (c *Consumer) Stop() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()

	c.cancel()
	close(c.closeCh)
	c.wg.Wait()
}

func (c *Consumer) run() {
	defer c.wg.Done()

	// Create a context that cancels when closeCh is closed
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-c.closeCh
		cancel()
	}()

	handler := &consumerGroupHandler{
		handler:        c.handler,
		config:         c.config,
		closeCh:        c.closeCh,
		processedCount: make(map[string]int),
	}

	for {
		select {
		case <-c.closeCh:
			log.Info().Msg("Kafka consumer stopping")
			cancel() // cleanup context
			return
		default:
		}

		if err := c.consumerGroup.Consume(ctx, c.topics, handler); err != nil {
			consumerErrors.WithLabelValues("all").Inc()
			log.Error().Err(err).Msg("Consumer group error")
		}

		if ctx.Err() != nil {
			return
		}
	}
}

type consumerGroupHandler struct {
	handler        MessageHandler
	config         *Config
	closeCh        chan struct{}
	processedCount map[string]int
	mu             sync.Mutex
}

func (h *consumerGroupHandler) Setup(session sarama.ConsumerGroupSession) error {
	log.Info().Msg("Consumer group setup")
	return nil
}

func (h *consumerGroupHandler) Cleanup(session sarama.ConsumerGroupSession) error {
	log.Info().Msg("Consumer group cleanup")
	return nil
}

func (h *consumerGroupHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	ctx, cancel := context.WithCancel(session.Context())
	defer cancel()

	workers := h.config.Consumer.Workers
	if workers < 1 {
		workers = 1
	}

	msgCh := make(chan *sarama.ConsumerMessage, workers*2)
	errCh := make(chan error, workers)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go h.worker(ctx, &wg, msgCh, errCh, session)
	}

	go func() {
		defer close(msgCh)
		for msg := range claim.Messages() {
			select {
			case msgCh <- msg:
			case <-ctx.Done():
				return
			case <-h.closeCh:
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			log.Error().Err(err).Msg("Worker error")
		}
	}

	return nil
}

func (h *consumerGroupHandler) worker(ctx context.Context, wg *sync.WaitGroup, msgCh <-chan *sarama.ConsumerMessage, errCh chan<- error, session sarama.ConsumerGroupSession) {
	defer wg.Done()

	for {
		select {
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			processCtx, cancel := context.WithTimeout(ctx, h.config.Consumer.ProcessingTimeout)
			err := h.handler(processCtx, msg)
			cancel()

			if err != nil {
				consumerErrors.WithLabelValues(msg.Topic).Inc()
				log.Error().Err(err).Str("topic", msg.Topic).Int32("partition", msg.Partition).Int64("offset", msg.Offset).Msg("Message processing failed")
				continue
			}

			session.MarkMessage(msg, "")
			consumedMessages.WithLabelValues(msg.Topic, string(msg.Partition), "success").Inc()

		case <-ctx.Done():
			return
		case <-h.closeCh:
			return
		}
	}
}
