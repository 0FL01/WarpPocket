//go:build !windows

package ui

import (
	"context"

	"github.com/0FL01/WarpPocket/internal/model"
)

func completeNativePicker(context.Context, chan<- struct{}, <-chan struct{}, string) error {
	return model.E("windows_required", "Эта нативная проверка требует Windows.")
}
