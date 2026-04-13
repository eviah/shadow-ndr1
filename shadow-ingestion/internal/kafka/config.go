package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"github.com/IBM/sarama"
)

// Config holds all Kafka configuration
type Config struct {
	// Broker addresses
	Brokers []string `yaml:"brokers" env:"KAFKA_BROKERS"`

	// Common
	ClientID string `yaml:"client_id" env:"KAFKA_CLIENT_ID" default:"shadow-ingestion"`

	// Producer specific
	Producer struct {
		// Required acks: 0, 1, or -1 (all)
		RequiredAcks int16 `yaml:"required_acks" default:"-1"`
		// Max number of retries
		MaxRetries int `yaml:"max_retries" default:"5"`
		// Retry backoff
		RetryBackoff time.Duration `yaml:"retry_backoff" default:"100ms"`
		// Idempotent (exactly once)
		Idempotent bool `yaml:"idempotent" default:"true"`
		// Compression: none, gzip, snappy, lz4, zstd
		Compression string `yaml:"compression" default:"snappy"`
		// Batch size in bytes
		BatchSize int `yaml:"batch_size" default:"16384"`
		// Flush messages when batch size is reached
		FlushBytes int `yaml:"flush_bytes" default:"16384"`
		// Flush messages after this delay
		FlushFrequency time.Duration `yaml:"flush_frequency" default:"1s"`
		// Enable idempotence (implies exactly once)
		EnableIdempotence bool `yaml:"enable_idempotence" default:"true"`
		// Transaction timeout (for transactional producer)
		TransactionTimeout time.Duration `yaml:"transaction_timeout" default:"60s"`
	} `yaml:"producer"`

	// Consumer specific
	Consumer struct {
		// Group ID
		GroupID string `yaml:"group_id" env:"KAFKA_GROUP_ID"`
		// Topics to consume
		Topics []string `yaml:"topics"`
		// Initial offset: oldest or newest
		InitialOffset string `yaml:"initial_offset" default:"newest"`
		// Max processing time per message (context timeout)
		ProcessingTimeout time.Duration `yaml:"processing_timeout" default:"30s"`
		// Number of concurrent workers per partition
		Workers int `yaml:"workers" default:"1"`
		// Session timeout
		SessionTimeout time.Duration `yaml:"session_timeout" default:"30s"`
		// Heartbeat interval
		HeartbeatInterval time.Duration `yaml:"heartbeat_interval" default:"3s"`
	} `yaml:"consumer"`

	// Security
	TLS struct {
		Enabled    bool   `yaml:"enabled" default:"false"`
		CAFile     string `yaml:"ca_file"`
		CertFile   string `yaml:"cert_file"`
		KeyFile    string `yaml:"key_file"`
		Insecure   bool   `yaml:"insecure" default:"false"`
		ServerName string `yaml:"server_name"`
	} `yaml:"tls"`

	SASL struct {
		Enabled   bool   `yaml:"enabled" default:"false"`
		Mechanism string `yaml:"mechanism" default:"PLAIN"` // PLAIN, SCRAM-SHA-256, SCRAM-SHA-512
		Username  string `yaml:"username"`
		Password  string `yaml:"password"`
	} `yaml:"sasl"`
}

// Validate checks if config is valid
func (c *Config) Validate() error {
	if len(c.Brokers) == 0 {
		return errors.New("no brokers configured")
	}
	if c.Consumer.GroupID == "" && len(c.Consumer.Topics) > 0 {
		return errors.New("consumer group ID required when consuming topics")
	}
	if c.SASL.Enabled && (c.SASL.Username == "" || c.SASL.Password == "") {
		return errors.New("SASL username and password required")
	}
	return nil
}

// NewSaramaConfig creates a sarama config from our config
func (c *Config) NewSaramaConfig() (*sarama.Config, error) {
	saramaCfg := sarama.NewConfig()

	// Version (use latest)
	saramaCfg.Version = sarama.V3_0_0_0

	// Client ID
	if c.ClientID != "" {
		saramaCfg.ClientID = c.ClientID
	}

	// Producer
	// Producer
	if c.Producer.RequiredAcks != 0 {
		saramaCfg.Producer.RequiredAcks = sarama.RequiredAcks(c.Producer.RequiredAcks)
	}
	saramaCfg.Producer.Retry.Max = c.Producer.MaxRetries
	saramaCfg.Producer.Retry.Backoff = c.Producer.RetryBackoff
	saramaCfg.Producer.Idempotent = c.Producer.Idempotent
	// EnableIdempotence does not exist in sarama; idempotence is set by Idempotent
	// saramaCfg.Producer.EnableIdempotence = c.Producer.EnableIdempotence

	switch c.Producer.Compression {
	case "gzip":
		saramaCfg.Producer.Compression = sarama.CompressionGZIP
	case "snappy":
		saramaCfg.Producer.Compression = sarama.CompressionSnappy
	case "lz4":
		saramaCfg.Producer.Compression = sarama.CompressionLZ4
	case "zstd":
		saramaCfg.Producer.Compression = sarama.CompressionZSTD
	default:
		saramaCfg.Producer.Compression = sarama.CompressionNone
	}
	saramaCfg.Producer.CompressionLevel = sarama.CompressionLevelDefault // תוקן שם הקבוע
	saramaCfg.Producer.Flush.Bytes = c.Producer.FlushBytes
	saramaCfg.Producer.Flush.Frequency = c.Producer.FlushFrequency
	saramaCfg.Producer.Return.Successes = true
	saramaCfg.Producer.Return.Errors = true
	// TLS
	if c.TLS.Enabled {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.TLS.Insecure,
		}
		if c.TLS.ServerName != "" {
			tlsConfig.ServerName = c.TLS.ServerName
		}
		if c.TLS.CAFile != "" {
			caCert, err := os.ReadFile(c.TLS.CAFile)
			if err != nil {
				return nil, err
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, errors.New("failed to parse CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}
		if c.TLS.CertFile != "" && c.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
			if err != nil {
				return nil, err
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		saramaCfg.Net.TLS.Enable = true
		saramaCfg.Net.TLS.Config = tlsConfig
	}

	// SASL
	if c.SASL.Enabled {
		saramaCfg.Net.SASL.Enable = true
		saramaCfg.Net.SASL.User = c.SASL.Username
		saramaCfg.Net.SASL.Password = c.SASL.Password
		switch c.SASL.Mechanism {
		case "SCRAM-SHA-256":
			saramaCfg.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		case "SCRAM-SHA-512":
			saramaCfg.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		default:
			saramaCfg.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		}
	}

	return saramaCfg, nil
}
