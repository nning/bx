package cmd

import (
	"fmt"

	"github.com/nning/bx/internal/crypto"
	"github.com/spf13/cobra"
)

var genCmd = &cobra.Command{
	Use:   "gen [length]",
	Short: "Generate a secure random password",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runGen,
}

func runGen(cmd *cobra.Command, args []string) error {
	useUpper, _ := cmd.Flags().GetBool("upper")
	useLower, _ := cmd.Flags().GetBool("lower")
	useDigits, _ := cmd.Flags().GetBool("digits")
	useSymbols, _ := cmd.Flags().GetBool("symbols")

	// --words switches to the passphrase generator; the password options do
	// not apply to it, and mixing them is an error rather than a silently
	// ignored flag.
	if words, _ := cmd.Flags().GetInt("words"); words > 0 || cmd.Flags().Changed("words") {
		if words <= 0 {
			return fmt.Errorf("--words must be at least 3")
		}
		if len(args) > 0 {
			return fmt.Errorf("a length argument is only valid for passwords; pass --words or nothing")
		}
		for _, f := range []string{"upper", "lower", "digits", "symbols"} {
			if cmd.Flags().Changed(f) {
				return fmt.Errorf("--%s is only valid for passwords", f)
			}
		}
		separator, _ := cmd.Flags().GetString("separator")
		capitalize, _ := cmd.Flags().GetBool("capitalize")
		includeNumber, _ := cmd.Flags().GetBool("number")
		passphrase, err := crypto.GeneratePassphrase(words, separator, capitalize, includeNumber)
		if err != nil {
			return err
		}
		fmt.Println(passphrase)
		return nil
	}

	var length int
	var err error

	length = 32

	if len(args) > 0 {
		length, err = parseIntFlag(args[0])
		if err != nil {
			return err
		}
	}

	password, err := crypto.GeneratePassword(length, useUpper, useLower, useDigits, useSymbols)
	if err != nil {
		return err
	}

	fmt.Println(password)
	return nil
}

func addGenFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("upper", "u", true, "Include uppercase letters")
	cmd.Flags().BoolP("lower", "l", true, "Include lowercase letters")
	cmd.Flags().BoolP("digits", "d", true, "Include digits (0-9)")
	cmd.Flags().BoolP("symbols", "s", true, "Include special characters (!@#$%^&* etc.)")
	cmd.Flags().Int("words", 0, "Generate a passphrase with this many words (3-64) from the EFF wordlist instead of a password")
	cmd.Flags().String("separator", "-", "Separator between passphrase words (with --words)")
	cmd.Flags().Bool("capitalize", false, "Capitalize the first letter of each passphrase word (with --words)")
	cmd.Flags().Bool("number", false, "Append a digit to one random passphrase word (with --words)")
}

func init() {
	addGenFlags(genCmd)
	rootCmd.AddCommand(genCmd)
}
