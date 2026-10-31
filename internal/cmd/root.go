package cmd

import (
	"fmt"
	"os"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var apiClient *client.Client

// activeAccountName holds the name of the currently active account, resolved
// at startup from the --account flag or the active_account config key.
var activeAccountName string

// accountFlag holds the value of the --account persistent flag before
// initConfig runs.
var accountFlag string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bx",
	Short: "A fast, maintainable Bitwarden client for self-hosted vaults",
	Long: `bx is a command-line interface for Bitwarden, optimized for self-hosted
Vaultwarden instances. It aims for speed, maintainability, and a superior
user experience compared to the official client.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.bx.yaml)")
	rootCmd.PersistentFlags().StringVar(&accountFlag, "account", "", "account name to use (overrides active_account in config)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".bx")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		// Silently ignore the "no config file found" case: bx works without a
		// pre-existing config (e.g. on first run before 'bx setup').  Any other
		// error (e.g. a malformed YAML file) is worth surfacing so the user
		// knows their config is broken.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "warning: error reading config file: %v\n", err)
		}
	}

	// Determine active account: --account flag takes precedence over config.
	if accountFlag != "" {
		if err := validateAccountName(accountFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		activeAccountName = accountFlag
	} else {
		name := viper.GetString("active_account")
		if name != "" {
			if err := validateAccountName(name); err != nil {
				cobra.CheckErr(err)
			}
		}
		activeAccountName = name
	}

	if err := validateConfiguredAccount(activeAccountName); err != nil {
		cobra.CheckErr(err)
	}

	// Propagate the active account name to the vault package so that it uses
	// per-account file paths for the vault cache and session timestamp.
	vault.ActiveAccount = activeAccountName

	server := accountSetting("server")
	if server != "" {
		migrateTokensToKeyring()
		apiClient = client.New(server)
		apiClient.Token = loadTokens().Session
	}
}

// accountSetting returns the value of key for the active account.
// Named accounts never inherit another account's identity or credentials.
// Only global convenience settings have a fallback.
func accountSetting(key string) string {
	if activeAccountName != "" {
		val := viper.GetString("accounts." + activeAccountName + "." + key)
		if val != "" || (key != "unlock_timeout" && key != "clipboard_clear_timeout") {
			return val
		}
	}
	return viper.GetString(key)
}

// setAccountSetting writes value to the active account's config section.
// When no account is active the value is written at the top level, preserving
// backward-compatible behavior for single-account configurations.
func setAccountSetting(key, value string) {
	if activeAccountName != "" {
		viper.Set("accounts."+activeAccountName+"."+key, value)
	} else {
		viper.Set(key, value)
	}
}

func validateConfiguredAccount(name string) error {
	if name == "" {
		return nil
	}
	if err := validateAccountName(name); err != nil {
		return err
	}
	if _, ok := viper.GetStringMap("accounts")[name]; !ok {
		return fmt.Errorf("account %q is not configured; run 'bx account add %s'", name, name)
	}
	return nil
}
