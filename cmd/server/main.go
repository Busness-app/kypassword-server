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
	"strconv"
	"syscall"
	"time"

	"kypassword-server/internal/api"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5877"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "./config"
	}

	retentionDays := 90
	if r := os.Getenv("RETENTION_DAYS"); r != "" {
		if val, err := strconv.Atoi(r); err == nil && val > 0 {
			retentionDays = val
		}
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

	srv, err := api.NewServer(api.Config{
		DataDir:       dataDir,
		ConfigDir:     configDir,
		PairingSecret: pairingSecret,
		RetentionDays: retentionDays,
	})
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	rootMux := http.NewServeMux()
	rootMux.Handle("/api/", srv.Routes())
	rootMux.Handle("/auth/", srv.Routes())

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

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("shutting down KyPassword server gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
	log.Println("server stopped.")
}
