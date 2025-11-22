package middleware

import (
	"math"
	"sync"
	"time"
)

// TrafficFeatures represents the traffic characteristics extracted for the AI model.
// These align with the features expected by the XGBoost model.
type TrafficFeatures struct {
	BwdPacketLengthStd  float64 `json:"bwd_packet_length_std"`
	BwdPacketLengthMean float64 `json:"bwd_packet_length_mean"`
	AvgPacketSize       float64 `json:"avg_packet_size"`
	FlowBytesSec        float64 `json:"flow_bytes_s"`
	FlowPacketsSec      float64 `json:"flow_packets_s"`
	FwdIATMean          float64 `json:"fwd_iat_mean"`
	FwdIATMax           float64 `json:"fwd_iat_max"`
	FwdIATMin           float64 `json:"fwd_iat_min"`
	FwdIATTotal         float64 `json:"fwd_iat_total"`
	TotalFwdPackets     int     `json:"total_fwd_packets"`
	SubflowFwdPackets   int     `json:"subflow_fwd_packets"`
}

// FlowStats maintains the state of a single client's traffic flow.
type FlowStats struct {
	mu sync.Mutex // Protects concurrent access to stats

	LastRequestTime time.Time
	FlowStartTime   time.Time

	// Sliding window data
	FwdPacketLengths []float64
	BwdPacketLengths []float64
	FwdIATs          []float64

	TotalFwdPkts int
	TotalBwdPkts int
}

// FlowTracker manages traffic statistics for all active clients.
type FlowTracker struct {
	flows sync.Map // Map[string]*FlowStats
}

// NewFlowTracker initializes a new flow tracking system.
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{}
}

// getOrCreateFlow retrieves an existing flow or initializes a new one.
func (ft *FlowTracker) getOrCreateFlow(clientIP string) *FlowStats {
	// Fast path: try load
	if v, ok := ft.flows.Load(clientIP); ok {
		return v.(*FlowStats)
	}

	// Slow path: initialize
	newFlow := &FlowStats{
		LastRequestTime:  time.Time{},
		FlowStartTime:    time.Now(),
		FwdPacketLengths: make([]float64, 0, 100), // Pre-allocate capacity
		BwdPacketLengths: make([]float64, 0, 100),
		FwdIATs:          make([]float64, 0, 100),
	}

	v, _ := ft.flows.LoadOrStore(clientIP, newFlow)
	return v.(*FlowStats)
}

// TrackRequest captures metadata from an incoming request.
// It returns the current feature set for the AI model.
func (ft *FlowTracker) TrackRequest(clientIP string, reqSize int64) *TrafficFeatures {
	stats := ft.getOrCreateFlow(clientIP)

	stats.mu.Lock()
	defer stats.mu.Unlock()

	now := time.Now()

	// Calculate Inter-Arrival Time (IAT)
	var fwdIAT float64
	if !stats.LastRequestTime.IsZero() {
		fwdIAT = float64(now.Sub(stats.LastRequestTime).Microseconds())
	}

	// Update statistics
	stats.TotalFwdPkts++
	stats.FwdPacketLengths = append(stats.FwdPacketLengths, float64(reqSize))
	if fwdIAT > 0 {
		stats.FwdIATs = append(stats.FwdIATs, fwdIAT)
	}
	stats.LastRequestTime = now

	// Maintain sliding window (keep last 100 samples)
	if len(stats.FwdPacketLengths) > 100 {
		stats.FwdPacketLengths = stats.FwdPacketLengths[1:]
	}
	if len(stats.FwdIATs) > 100 {
		stats.FwdIATs = stats.FwdIATs[1:]
	}

	// Compile features
	return &TrafficFeatures{
		TotalFwdPackets:   stats.TotalFwdPkts,
		SubflowFwdPackets: stats.TotalFwdPkts, // Simplified: subflow = flow
		FwdIATMean:        calculateMean(stats.FwdIATs),
		FwdIATMax:         calculateMax(stats.FwdIATs),
		FwdIATMin:         calculateMin(stats.FwdIATs),
		FwdIATTotal:       calculateSum(stats.FwdIATs),
	}
}

// UpdateResponseStats captures metadata from the outgoing response.
func (ft *FlowTracker) UpdateResponseStats(clientIP string, respSize int64, features *TrafficFeatures) {
	stats := ft.getOrCreateFlow(clientIP)

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.TotalBwdPkts++
	stats.BwdPacketLengths = append(stats.BwdPacketLengths, float64(respSize))

	if len(stats.BwdPacketLengths) > 100 {
		stats.BwdPacketLengths = stats.BwdPacketLengths[1:]
	}

	// Compute bidirectional features
	bwdMean := calculateMean(stats.BwdPacketLengths)
	features.BwdPacketLengthMean = bwdMean
	features.BwdPacketLengthStd = calculateStdDev(stats.BwdPacketLengths, bwdMean)

	// Combine Fwd + Bwd for average size
	// Note: In high production, we might optimize avoiding the append here
	totalPackets := float64(stats.TotalFwdPkts + stats.TotalBwdPkts)
	totalSize := calculateSum(stats.FwdPacketLengths) + calculateSum(stats.BwdPacketLengths)
	if totalPackets > 0 {
		features.AvgPacketSize = totalSize / totalPackets
	}
}

// --- Statistical Helpers ---

func calculateMean(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	var sum float64
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

func calculateStdDev(data []float64, mean float64) float64 {
	if len(data) == 0 {
		return 0
	}
	var sumSq float64
	for _, v := range data {
		diff := v - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(data)))
}

func calculateMax(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	max := data[0]
	for _, v := range data {
		if v > max {
			max = v
		}
	}
	return max
}

func calculateMin(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	min := data[0]
	for _, v := range data {
		if v < min {
			min = v
		}
	}
	return min
}

func calculateSum(data []float64) float64 {
	var sum float64
	for _, v := range data {
		sum += v
	}
	return sum
}
