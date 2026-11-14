// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package settings

import (
	"os"
	"strings"

	"github.com/gsoultan/ares-server/internal/ai"
)

// Environment-variable fallbacks for OSINT provider credentials. Stored settings
// take precedence; these let an existing env-based deployment keep working and
// are consulted only when a workspace has not configured the secret in-app.
const (
	envShodanKey    = "SHODAN_API_KEY"
	envCensysID     = "CENSYS_API_ID"
	envCensysSecret = "CENSYS_API_SECRET"
	envHIBPKey      = "HIBP_API_KEY"
)

// envSecretFallback returns the environment-supplied value for a secret name, or
// "" when none is set. The AI API key is sourced through ai.ConfigFromEnv so its
// vendor-specific fallbacks (ANTHROPIC_API_KEY, OPENAI_API_KEY, …) apply.
func envSecretFallback(name string) string {
	switch name {
	case SecretAIAPIKey:
		return strings.TrimSpace(ai.ConfigFromEnv().APIKey)
	case SecretShodanKey:
		return strings.TrimSpace(os.Getenv(envShodanKey))
	case SecretCensysID:
		return strings.TrimSpace(os.Getenv(envCensysID))
	case SecretCensysSecret:
		return strings.TrimSpace(os.Getenv(envCensysSecret))
	case SecretHIBPKey:
		return strings.TrimSpace(os.Getenv(envHIBPKey))
	default:
		return ""
	}
}
