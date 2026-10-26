package authservice

import (
	"fmt"
	"os"
	"strings"
)

// Config holds configuration parameters for n8n-auth-service.
type Config struct {
	Port             string
	LogLevel         string
	DBURL            string
	KeycloakURL      string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	N8NBaseURL       string
	N8NPublicURL     string
	AdminAPIToken    string
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}
	logLevel := strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	if logLevel == "" {
		logLevel = "info"
	}

	dbURL := strings.TrimSpace(os.Getenv("DB_URL"))
	if dbURL == "" {
		dbHost := strings.TrimSpace(os.Getenv("DB_HOST"))
		dbPass := strings.TrimSpace(os.Getenv("DB_PASSWORD"))
		if dbPass == "" {
			dbPass = strings.TrimSpace(os.Getenv("PG_PASSWORD"))
		}
		if dbPass == "" {
			dbPass = strings.TrimSpace(os.Getenv("DB_POSTGRESDB_PASSWORD"))
		}
		if dbHost != "" && dbPass != "" {
			dbPort := os.Getenv("DB_PORT")
			if dbPort == "" {
				dbPort = "5432"
			}
			dbUser := os.Getenv("DB_USER")
			if dbUser == "" {
				dbUser = "lab_worker"
			}
			dbName := os.Getenv("DB_NAME")
			if dbName == "" {
				dbName = "n8n_db"
			}
			dbSSL := os.Getenv("DB_SSLMODE")
			if dbSSL == "" {
				dbSSL = "disable"
			}
			dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", dbUser, dbPass, dbHost, dbPort, dbName, dbSSL)
		}
	}
	if dbURL == "" {
		return nil, fmt.Errorf("database configuration required (DB_URL or DB_HOST + DB_PASSWORD)")
	}

	kcURL := strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_URL")), "/")
	if kcURL == "" {
		kcURL = "https://auth.lab.local/realms/lab"
	}

	clientID := strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID"))
	if clientID == "" {
		clientID = "n8n-lab"
	}

	clientSecret := strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET"))
	if clientSecret == "" {
		clientSecret = "N8nClientSecretLab2026#"
	}

	redirectURL := strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL"))
	if redirectURL == "" {
		redirectURL = "https://n8n.lab.local/sso/callback"
	}

	n8nBaseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("N8N_BASE_URL")), "/")
	if n8nBaseURL == "" {
		n8nBaseURL = "http://n8n-dev.lab-dev.svc:5678"
	}

	n8nPublicURL := strings.TrimRight(strings.TrimSpace(os.Getenv("N8N_PUBLIC_URL")), "/")
	if n8nPublicURL == "" {
		n8nPublicURL = "https://n8n.lab.local"
	}

	adminAPIToken := strings.TrimSpace(os.Getenv("ADMIN_API_TOKEN"))
	if adminAPIToken == "" {
		// #nosec G101 - default fallback for local dev/lab environment
		adminAPIToken = "N8nAdminApiTokenLab2026#"
	}

	return &Config{
		Port:             port,
		LogLevel:         logLevel,
		DBURL:            dbURL,
		KeycloakURL:      kcURL,
		OIDCClientID:     clientID,
		OIDCClientSecret: clientSecret,
		OIDCRedirectURL:  redirectURL,
		N8NBaseURL:       n8nBaseURL,
		N8NPublicURL:     n8nPublicURL,
		AdminAPIToken:    adminAPIToken,
	}, nil
}
