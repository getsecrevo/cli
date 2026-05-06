package main

import (
	"os"

	"github.com/getsecrevo/cli/internal/app"
)

func main() {
	if err := app.Execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		os.Exit(1)
	}
}
