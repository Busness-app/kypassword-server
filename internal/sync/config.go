package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadSCIMToken resolves an explicit deployment token before a restored capsule's copy.
func LoadSCIMToken(configDir, configured string) (string, error) {
	if configured == "" {
		data, err := os.ReadFile(filepath.Join(configDir, "scim.token"))
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("read SCIM token: %w", err)
		}
		configured = string(data)
	}
	if configured != "" && (len(configured) < 32 || len(configured) > 512 || strings.ContainsAny(configured, " \t\r\n")) {
		return "", fmt.Errorf("SCIM token must contain 32 to 512 non-whitespace characters")
	}
	return configured, nil
}
