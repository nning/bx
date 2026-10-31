package main

import "github.com/nning/bx/internal/cmd"

var Version = "dev"

func main() {
	cmd.Execute(Version)
}
