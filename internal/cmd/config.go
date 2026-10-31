package cmd

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  `Manage configuration settings for bx.`,
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long:  `Set a configuration value. Valid keys: unlock_timeout, clipboard_clear_timeout`,
	Args:  cobra.ExactArgs(2),
	Run: func(_ *cobra.Command, args []string) {
		key := args[0]
		value := args[1]

		// Validate key
		validKeys := map[string]bool{
			"unlock_timeout":          true,
			"clipboard_clear_timeout": true,
		}
		if !validKeys[key] {
			cobra.CheckErr(fmt.Errorf("invalid key: %s. Valid keys are: unlock_timeout, clipboard_clear_timeout\nUse 'bx setup' or 'bx account add <name>' to configure server and email", key))
		}

		switch key {
		case "unlock_timeout":
			// unlock_timeout must be a non-negative integer; validate before writing
			// so that viper.GetInt() can never silently coerce a bad value to 0.
			if err := validateUnlockTimeout(value); err != nil {
				cobra.CheckErr(err)
			}
		case "clipboard_clear_timeout":
			if err := validateClipboardClearTimeout(value); err != nil {
				cobra.CheckErr(err)
			}
		}

		viper.Set(key, value)

		configFile, err := configFilePath()
		cobra.CheckErr(err)
		_, statErr := os.Lstat(configFile)
		cobra.CheckErr(saveConfig())
		if os.IsNotExist(statErr) {
			fmt.Printf("Configuration created at %s\n", configFile)
		}
		fmt.Printf("Configuration saved: %s = %s\n", key, value)
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		key := args[0]

		validKeys := map[string]bool{
			"unlock_timeout":          true,
			"clipboard_clear_timeout": true,
		}
		if !validKeys[key] {
			cobra.CheckErr(fmt.Errorf("invalid key: %s. Valid keys are: unlock_timeout, clipboard_clear_timeout\nUse 'bx account list' to view account settings", key))
		}

		val := viper.Get(key)
		if val == nil {
			fmt.Println("Not set")
		} else {
			fmt.Println(val)
		}
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
}

// validateUnlockTimeout returns an error if value is not a valid non-negative
// integer for the unlock_timeout configuration key.
func validateUnlockTimeout(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("invalid value for unlock_timeout: %q must be an integer", value)
	}
	if n < 0 {
		return fmt.Errorf("invalid value for unlock_timeout: %d must be >= 0 (use 0 to disable session caching)", n)
	}
	return nil
}

// validateClipboardClearTimeout returns an error if value is not a valid
// non-negative integer for the clipboard_clear_timeout configuration key.
// Values that would overflow time.Duration when converted to seconds are
// rejected.
func validateClipboardClearTimeout(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("invalid value for clipboard_clear_timeout: %q must be an integer", value)
	}
	if n < 0 {
		return fmt.Errorf("invalid value for clipboard_clear_timeout: %d must be >= 0 (use 0 to disable clipboard clearing)", n)
	}
	const maxSeconds = math.MaxInt64 / int64(time.Second)
	if int64(n) > maxSeconds {
		return fmt.Errorf("invalid value for clipboard_clear_timeout: %d exceeds maximum allowed value of %d seconds", n, maxSeconds)
	}
	return nil
}
