package cmd

import (
	"fmt"
	"strconv"
)

func parseIntFlag(s string) (int, error) {
	result, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid length: %q", s)
	}
	if result < 0 {
		return 0, fmt.Errorf("invalid length: %q (must be non-negative)", s)
	}
	return result, nil
}
