package main

import (
	"testing"

	"github.com/getsecrevo/cli/internal/app"
)

func TestMainPackageImportsApp(t *testing.T) {
	_ = app.NewRootCommand
}
