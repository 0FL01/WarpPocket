package model

type State string

const (
	Disconnected State = "disconnected"
	Connecting   State = "connecting"
	Connected    State = "connected"
	Failed       State = "error"
)

// Snapshot is an immutable, secret-free view of the controller.
type Snapshot struct {
	State           State
	Code, Message   string
	Endpoint        Endpoint
	LatencyMS       float64
	Searching, Busy bool
	SearchRole      string

	// Recovering is an established session being restored, not a fifth State.
	// It implies Connecting and Busy, with no endpoint, latency or error outcome.
	Recovering bool
}

// Event fields are typed; nil Found means that a progress event did not update
// the success count, rather than resetting it to zero.
// State event codes recovery_started/recovered identify transitions only; they
// are not persistent Snapshot.Code error outcomes.
type Event struct {
	State                            State
	Type, Stage, Role, Code, Message string
	Endpoint                         Endpoint
	Checked, Limit                   int
	Found                            *int
	Saved                            bool
	Best                             Endpoint
}

func Count(n int) *int { return &n }
