package ui

import "github.com/0FL01/WarpPocket/internal/model"

// Startup failures use the same native window, but cannot start any operation.
type startupError struct{ message string }

func (s *startupError) Status() model.Snapshot {
	return model.Snapshot{State: model.Failed, Message: s.message, Busy: true}
}
func (*startupError) PollEvents() []model.Event { return nil }
func (*startupError) Connect(bool)              {}
func (*startupError) Disconnect()               {}
func (*startupError) StartSearch(bool)          {}
func (*startupError) CancelSearch()             {}
func (*startupError) Close()                    {}
func ShowError(err error) error                 { return Run(&startupError{model.SafeMessage(err)}, Options{}) }
