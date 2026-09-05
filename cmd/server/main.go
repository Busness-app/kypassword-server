package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/Busness-app/kypassword-server/internal/api"
	"github.com/Busness-app/kypassword-server/internal/backup"
	"github.com/Busness-app/kypassword-server/internal/sso"
	"github.com/Busness-app/kypassword-server/internal/users"
)

func main() {
	if handled, err := runMigrationCommand(os.Args[1:], os.Stdout); handled {
		if err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "5877"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	configDir := configDirFromEnv()
	lock, err := acquireInstanceLock(configDir)
	if err != nil {
		log.Fatal(err)
	}
	defer lock.Close()

	requireMigratedAccounts(configDir)
	requireIdentityProvider(configDir)

	retentionDays := 90
	if r := os.Getenv("RETENTION_DAYS"); r != "" {
		if val, err := strconv.Atoi(r); err == nil && val > 0 {
			retentionDays = val
		}
	}
	backupConfig, err := backup.ConfigFromEnv()
	if err != nil {
		log.Fatalf("KYPASSWORD_BACKUP_DEPOSIT_INTERVAL: %v", err)
	}

	pairingSecret := os.Getenv("PAIRING_SECRET")
	if pairingSecret == "" {
		secretFile := filepath.Join(configDir, "pairing.secret")
		if data, err := os.ReadFile(secretFile); err == nil && len(data) > 0 {
			pairingSecret = string(data)
		} else {
			buf := make([]byte, 32)
			_, _ = rand.Read(buf)
			pairingSecret = hex.EncodeToString(buf)
			_ = os.MkdirAll(configDir, 0700)
			_ = os.WriteFile(secretFile, []byte(pairingSecret), 0600)
		}
	}

	if backupConfig.AllowPrivate {
		log.Print("[BACKUP] private KyRecovery destinations explicitly enabled")
	}
	srv, err := api.NewServer(api.Config{
		DataDir:       dataDir,
		ConfigDir:     configDir,
		PairingSecret: pairingSecret,
		SCIMToken:     os.Getenv("KYPASSWORD_SCIM_TOKEN"),
		RetentionDays: retentionDays,
		AppVersion:    buildVersion(),
		Backup:        backupConfig,
	})
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	rootMux := http.NewServeMux()
	rootMux.Handle("/api/", srv.Routes())
	rootMux.Handle("/auth/", srv.Routes())
	rootMux.Handle("/scim/", srv.Routes())

	// Static SPA file serving
	webDir := os.Getenv("WEB_DIR")
	if webDir == "" {
		if _, err := os.Stat("/app/frontend/dist"); err == nil {
			webDir = "/app/frontend/dist"
		} else if _, err := os.Stat("./frontend/dist"); err == nil {
			webDir = "./frontend/dist"
		} else if _, err := os.Stat("./dist"); err == nil {
			webDir = "./dist"
		}
	}
	if webDir != "" {
		fs := http.FileServer(http.Dir(webDir))
		rootMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			path := filepath.Join(webDir, filepath.Clean(r.URL.Path))
			if _, err := os.Stat(path); os.IsNotExist(err) {
				// Fallback to index.html for SPA router
				http.ServeFile(w, r, filepath.Join(webDir, "index.html"))
				return
			}
			fs.ServeHTTP(w, r)
		})
	} else {
		// Development fallback
		rootMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>KyPassword Server</title></head><body style="background:#0d0f14;color:#4deeea;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;"><div><h1>KyPassword Server</h1><p style="color:#888;">API Daemon Running on Port ` + port + `</p></div></body></html>`))
				return
			}
			http.NotFound(w, r)
		})
	}

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      rootMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("KyPassword server listening on :%s (data: %s, config: %s)", port, dataDir, configDir)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	schedulerCtx, stopScheduler := context.WithCancel(context.Background())
	schedulerDone := make(chan struct{})
	go func() {
		defer close(schedulerDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-schedulerCtx.Done():
				return
			case <-ticker.C:
				srv.RunScheduledDeposit(schedulerCtx)
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
	stopScheduler()

	log.Println("shutting down KyPassword server gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
	<-schedulerDone
	srv.WaitForBackups()
	srv.Close()
	log.Println("server stopped.")
}

func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// requireMigratedAccounts refuses to start while any active account has no KySignOn
// identity. It runs before the listener opens, so a half-migrated upgrade never serves a
// single request — such an account cannot sign in, and replication would provision a
// second account for the same person alongside it.
func requireMigratedAccounts(configDir string) {
	store, err := users.NewStore(configDir)
	if err != nil {
		log.Fatalf("failed to read accounts from %s: %v", configDir, err)
	}

	unlinked := users.UnlinkedActive(store)
	if len(unlinked) == 0 {
		return
	}

	log.Printf("KyPassword now authenticates only through KySignOn, and %d active account(s) have no KySignOn identity:", len(unlinked))
	for _, u := range unlinked {
		log.Printf("  - %s (id %s)", u.Username, u.ID)
	}
	log.Printf("Link each one:      kypassword-server link-sso --username <name> --sub <kysignon-user-id>")
	log.Printf("Or retire it:       kypassword-server deactivate --username <name>")
	log.Printf("The KySignOn user ID is the value shown in its admin user list, and is the same value it puts in the OIDC 'sub' claim.")
	os.Exit(1)
}

// requireIdentityProvider refuses to start without an identity provider. KySignOn is the
// only authenticator, so a server without one can authenticate nobody — starting would
// only serve 503s to every sign-in attempt, and there is no local admin who could fix it
// from the UI.
func requireIdentityProvider(configDir string) {
	settings := sso.NewStore(configDir).Load()
	if settings.Enabled && settings.IssuerURL != "" && settings.ClientID != "" {
		// A client secret is deliberately not required here. sso.ExchangeCode omits it
		// when empty and always sends the PKCE code_verifier, so a public client is a
		// supported configuration and refusing to start would break one. But a missing
		// secret is far more often an incomplete confidential setup than a deliberate
		// public one, and that only surfaces as a token-exchange failure at first login.
		// So say which mode is in force, at boot, where an operator will see it.
		mode := "confidential client"
		if settings.ClientSecret == "" {
			mode = "public client (no client secret configured; token exchange relies on PKCE alone)"
		}
		log.Printf("KySignOn: %s, issuer %s, client %s", mode, settings.IssuerURL, settings.ClientID)
		return
	}

	log.Printf("KyPassword authenticates only through KySignOn, and no identity provider is configured.")
	log.Printf("Set these and restart:")
	log.Printf("  %s        e.g. https://signon.example.com", sso.EnvIssuer)
	log.Printf("  %s     the client ID KySignOn issued for KyPassword", sso.EnvClientID)
	log.Printf("  %s the matching client secret, required for a confidential client", sso.EnvClientSecret)
	log.Printf("Optional: %s, %s (defaults to true).", sso.EnvRedirectURI, sso.EnvAutoProvision)
	log.Printf("These take precedence over %s/sso.json and cannot be changed from the admin UI.", configDir)
	os.Exit(1)
}
