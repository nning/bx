package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/nning/bx/internal/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var loginCmd = &cobra.Command{
	Use:   "login [email]",
	Short: "Log in to the Vaultwarden/Bitwarden server",
	Args:  cobra.MaximumNArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		var server string
		if activeAccountName != "" {
			server = viper.GetString("accounts." + activeAccountName + ".server")
			if server == "" {
				cobra.CheckErr(fmt.Errorf("account %q is not configured. Run 'bx account add %s' to set it up", activeAccountName, activeAccountName))
			}
		} else {
			server = viper.GetString("server")
			if server == "" {
				cobra.CheckErr(fmt.Errorf("server URL not configured. Run 'bx setup' or 'bx account add <name>'"))
			}
		}

		var email string
		if len(args) > 0 {
			email = args[0]
		} else {
			if activeAccountName != "" {
				email = viper.GetString("accounts." + activeAccountName + ".email")
			} else {
				email = viper.GetString("email")
			}
			if email == "" {
				var err error
				email, err = promptLine("Email: ")
				cobra.CheckErr(err)
			}
		}
		email = strings.TrimSpace(email)

		if email == "" {
			cobra.CheckErr(fmt.Errorf("email is required"))
		}

		if err := performLogin(server, email); err != nil {
			cobra.CheckErr(err)
		}
		fmt.Println("Logged in successfully.")
	},
}

// validateTOTPCode normalizes a TOTP code by stripping spaces and then
// verifies that the result is 6 to 8 decimal digits, the lengths RFC 4226
// (which RFC 6238 builds on) allows.  It returns the normalized code and a
// descriptive error when the format is invalid.
func validateTOTPCode(code string) (string, error) {
	code = strings.ReplaceAll(code, " ", "")
	if len(code) < 6 || len(code) > 8 {
		return "", fmt.Errorf("invalid TOTP code: must be 6 to 8 digits (got %d characters)", len(code))
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return "", fmt.Errorf("invalid TOTP code: must contain only digits")
		}
	}
	return code, nil
}

// performLogin runs the full login flow against server using email.
// It prompts for the master password and handles TOTP two-factor authentication.
// On success it updates viper with the session token and saves the config file.
func performLogin(server, email string) error {
	if err := checkServerURL(server); err != nil {
		return err
	}

	password, err := readPassword()
	if err != nil {
		return err
	}

	deviceID := accountSetting("device_id")
	if deviceID == "" {
		deviceID = uuid.New().String()
		setAccountSetting("device_id", deviceID)
	}

	c := client.New(server)
	tokenResp, err := c.Login(email, password, deviceID, "", "")
	if err != nil {
		if tfrErr, ok := err.(*client.ErrTwoFactorRequired); ok {
			var hasTOTP bool
			for _, p := range tfrErr.Response.TwoFactorProviders {
				if p == "0" {
					hasTOTP = true
					break
				}
			}

			if !hasTOTP {
				return fmt.Errorf("two-factor authentication required, but TOTP (provider 0) is not available. Available providers: %v", tfrErr.Response.TwoFactorProviders)
			}

			line, err := promptLine("Two-factor code (TOTP): ")
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}

			totpCode, err := validateTOTPCode(line)
			if err != nil {
				return err
			}

			tokenResp, err = c.Login(email, password, deviceID, totpCode, "0")
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	storeTokens(accountTokens{Session: tokenResp.AccessToken, Refresh: tokenResp.RefreshToken})
	setAccountSetting("protected_key", tokenResp.Key)
	setAccountSetting("email", email)

	return saveConfig()
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
