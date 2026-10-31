package cmd

import "github.com/nning/bx/internal/client"

func checkServerURL(raw string) error { return client.ValidateServerURL(raw) }
