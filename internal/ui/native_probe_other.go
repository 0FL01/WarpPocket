//go:build !windows

package ui

import (
	"context"

	"github.com/0FL01/WarpPocket/internal/model"
)

func closeNativePicker(context.Context, chan<- struct{}, <-chan struct{}) error {
	return model.E("windows_required", "Эта нативная проверка требует Windows.")
}
