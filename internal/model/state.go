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
}

// Event fields are typed; nil Found means that a progress event did not update
// the success count, rather than resetting it to zero.
type Event struct {
	Type, Stage, Role, Code, Message string
	Endpoint                         Endpoint
	Checked, Limit                   int
	Found                            *int
	Saved                            bool
	Best                             Endpoint
}

func Count(n int) *int { return &n }
