package kafka

import (
	"context"

	"time"

	"github.com/IBM/sarama"
)

// DLQProducer is a specialized producer for dead letter queue.
type DLQProducer struct {
	producer *Producer
	topic    string
}

// NewDLQProducer creates a producer dedicated to DLQ.
func NewDLQProducer(cfg *Config, dlqTopic string) (*DLQProducer, error) {
	producer, err := NewProducer(cfg, dlqTopic)
	if err != nil {
		return nil, err
	}
	return &DLQProducer{
		producer: producer,
		topic:    dlqTopic,
	}, nil
}

// Send sends a failed message to the DLQ.
func (d *DLQProducer) Send(ctx context.Context, originalMsg *sarama.ConsumerMessage, err error, extra map[string]interface{}) error {
	dlqMsg := struct {
		OriginalTopic     string                 `json:"original_topic"`
		OriginalPartition int32                  `json:"original_partition"`
		OriginalOffset    int64                  `json:"original_offset"`
		OriginalKey       string                 `json:"original_key"`
		OriginalValue     string                 `json:"original_value"`
		Error             string                 `json:"error"`
		Timestamp         int64                  `json:"timestamp"`
		Extra             map[string]interface{} `json:"extra,omitempty"`
	}{
		OriginalTopic:     originalMsg.Topic,
		OriginalPartition: originalMsg.Partition,
		OriginalOffset:    originalMsg.Offset,
		OriginalKey:       string(originalMsg.Key),
		OriginalValue:     string(originalMsg.Value),
		Error:             err.Error(),
		Timestamp:         time.Now().Unix(),
		Extra:             extra,
	}
	return d.producer.Send(ctx, d.topic, "", dlqMsg)
}

// Close closes the underlying producer.
func (d *DLQProducer) Close() error {
	return d.producer.Close()
}
