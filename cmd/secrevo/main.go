package main

import (
	"fmt"
	"os"

	"github.com/getsecrevo/cli/internal/app"
)

func main() {
	err := app.Execute(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		// `secrevo run` exits with the child process's exit code; everything
		// else surfaces a generic 1 with the error text.
		code := app.ExitCode(err)
		if code == 1 {
			fmt.Fprintln(os.Stderr, "secrevo:", err)
		}
		os.Exit(code)
	}
}
