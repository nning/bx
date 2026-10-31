package cmd

import (
	"fmt"

	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault by clearing the cached session",
	Long: `Lock the vault immediately by removing the cached session.

After locking, the next command that accesses the vault will prompt for the
master password again. This is useful when stepping away from the terminal
before the unlock timeout expires.`,
	Run: func(_ *cobra.Command, _ []string) {
		if err := vault.ClearSession(); err != nil {
			cobra.CheckErr(err)
		}
		fmt.Println("Vault locked.")
	},
}

func init() {
	rootCmd.AddCommand(lockCmd)
}
