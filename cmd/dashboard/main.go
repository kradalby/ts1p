package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	d, err := buildDashboard()
	if err != nil {
		fmt.Fprintln(os.Stderr, "build dashboard:", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal dashboard:", err)
		os.Exit(1)
	}

	_, err = os.Stdout.Write(append(out, '\n'))
	if err != nil {
		fmt.Fprintln(os.Stderr, "write dashboard:", err)
		os.Exit(1)
	}
}
