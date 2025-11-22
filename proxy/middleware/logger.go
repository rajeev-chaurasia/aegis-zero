package middleware

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/IBM/sarama"
)

// RequestLog represents the structured log entry sent to the AI Engine.
// It matches the schema expected by the Python consumer.
type RequestLog struct {
	Timestamp    time.Time        `json:"timestamp"`
	ClientIP     string           `json:"client_ip"`
	Method       string           `json:"method"`
	URL          string           `json:"url"`
	UserAgent    string           `json:"user_agent"`
	Status       int              `json:"status"`
	Duration     int64            `json:"duration_ms"`
	RequestSize  int64            `json:"request_size"`
	ResponseSize int64            `json:"response_size"`
	Protocol     string           `json:"protocol"`
	Features     *TrafficFeatures `json:"features,omitempty"`
}

// LoggerMiddleware handles request logging and feature extraction for the pipeline.
type LoggerMiddleware struct {
	producer    sarama.SyncProducer
	topic       string
	flowTracker *FlowTracker
}

// NewLoggerMiddleware initializes the Kafka producer and internal tracker.
func NewLoggerMiddleware(brokers []string, topic string) (*LoggerMiddleware, error) {
	// Configure Kafka producer for reliability and speed
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Producer.RequiredAcks = sarama.WaitForLocal // Local ack is sufficient for high throughput
	config.Producer.Retry.Max = 3

	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		return nil, err
	}

	return &LoggerMiddleware{
		producer:    producer,
		topic:       topic,
		flowTracker: NewFlowTracker(),
	}, nil
}

// Close ensures the Kafka connection is terminated gracefully.
func (lm *LoggerMiddleware) Close() error {
	return lm.producer.Close()
}

// Handler acts as the middleware function to intercept HTTP traffic.
func (lm *LoggerMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 1. Feature Extraction (Pre-Request)
		clientIP := extractClientIPLogger(r)

		// Estimate request size (Header + Body) including overhead
		reqSize := r.ContentLength
		if reqSize < 0 {
			reqSize = 0
		}
		// Add standard overhead for HTTP headers estimate
		reqSize += 500

		// Update flow state and calculate initial feature set
		features := lm.flowTracker.TrackRequest(clientIP, reqSize)

		// 2. Request Processing
		// Wrap ResponseWriter to capture status code and content size
		ww := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(ww, r)

		// 3. Post-Request Statistics
		duration := time.Since(start).Milliseconds()

		// Update stats with actual response size (Bwd Packet Length)
		lm.flowTracker.UpdateResponseStats(clientIP, ww.responseSize, features)

		// 4. Async Log Shipping
		// Construct the log entry for the AI Engine
		logEntry := RequestLog{
			Timestamp:    start.UTC(),
			ClientIP:     clientIP,
			Method:       r.Method,
			URL:          r.URL.String(),
			UserAgent:    r.UserAgent(),
			Status:       ww.statusCode,
			Duration:     duration,
			RequestSize:  reqSize,
			ResponseSize: ww.responseSize,
			Protocol:     r.Proto,
			Features:     features,
		}

		// shipLog handles the serialization and kafka produce
		go lm.shipLog(logEntry)
	})
}

// shipLog sends the log entry to Kafka on a separate goroutine.
func (lm *LoggerMiddleware) shipLog(entry RequestLog) {
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Error marshalling log entry: %v", err)
		return
	}

	msg := &sarama.ProducerMessage{
		Topic: lm.topic,
		Key:   sarama.StringEncoder(entry.ClientIP), // Key by IP for partition locality
		Value: sarama.ByteEncoder(data),
	}

	if _, _, err := lm.producer.SendMessage(msg); err != nil {
		log.Printf("Failed to send log to Kafka: %v", err)
	}
}

// Helper: extractClientIPLogger gets the real client IP.
func extractClientIPLogger(r *http.Request) string {
	// Check standard headers
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// responseWriterWrapper captures HTTP status code and response size.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode   int
	responseSize int64
}

func (w *responseWriterWrapper) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriterWrapper) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.responseSize += int64(n)
	return n, err
}
