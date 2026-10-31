package cmd

import (
	"fmt"

	"github.com/nning/bx/internal/client"
	"github.com/nning/bx/internal/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive first-run setup: configure server, log in, and fetch vault",
	Long: `Setup guides you through the three steps needed to start using bx:

  1. Server URL   — the URL of your Bitwarden/Vaultwarden instance
  2. Login        — your account email and master password (+ 2FA if enabled)
  3. Vault fetch  — downloads and caches the encrypted vault locally

If a value is already configured it will be shown as the default and you can
press Enter to keep it.`,
	Run: func(_ *cobra.Command, _ []string) {
		// When no account is active yet (first-run), create the config
		// directly under accounts.default so that it is already in
		// multi-account format from the start.
		if activeAccountName == "" {
			const defaultName = "default"
			activeAccountName = defaultName
			vault.ActiveAccount = defaultName
			viper.Set("active_account", defaultName)
		}

		// --- Step 1: server URL ---
		server := accountSetting("server")
		fmt.Printf("Server URL")
		if server != "" {
			fmt.Printf(" [%s]", server)
		}
		serverInput, err := promptLine(": ")
		cobra.CheckErr(err)
		if serverInput != "" {
			server = serverInput
		}
		if server == "" {
			cobra.CheckErr(fmt.Errorf("server URL is required"))
		}
		cobra.CheckErr(checkServerURL(server))
		// Persist the server URL now so that if login fails, the user does not
		// have to re-enter it on the next attempt.
		setAccountSetting("server", server)
		if err := saveConfig(); err != nil {
			cobra.CheckErr(err)
		}

		// --- Step 2: email ---
		email := accountSetting("email")
		fmt.Printf("Email")
		if email != "" {
			fmt.Printf(" [%s]", email)
		}
		emailInput, err := promptLine(": ")
		cobra.CheckErr(err)
		if emailInput != "" {
			email = emailInput
		}
		if email == "" {
			cobra.CheckErr(fmt.Errorf("email is required"))
		}

		// --- Step 3: login (prompts for master password + optional 2FA) ---
		if err := performLogin(server, email); err != nil {
			cobra.CheckErr(err)
		}
		fmt.Println("Logged in successfully.")

		// Refresh the global API client with the newly obtained token so that
		// performFetch can use it immediately without restarting the process.
		apiClient = client.New(server)
		apiClient.Token = loadTokens().Session

		// --- Step 4: fetch vault ---
		if err := performFetch(); err != nil {
			cobra.CheckErr(err)
		}

		fmt.Println("\nSetup complete! Run 'bx list' to see your vault items.")
	},
}

func init() {
	rootCmd.AddCommand(setupCmd)
}
