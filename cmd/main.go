package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nostr-nip46-signer/internal/web"
)

func main() {
	relayURLs := []string{
		"wss://nos.lol",        // <--- Primer lugar (más estable)
		"wss://nostr.wine",     // <--- Segundo lugar
		"wss://relay.damus.io", // <--- Fallback
	}

	app := web.NewServer(relayURLs)

	// El token solo se muestra si se generó automáticamente.
	// Si viene de ADMIN_TOKEN, ya lo conoce el operador y no se escribe en logs.
	if os.Getenv("ADMIN_TOKEN") == "" {
		log.Printf("Admin token (pégalo en la interfaz): %s", app.AdminToken())
	} else {
		log.Println("Admin token cargado desde ADMIN_TOKEN")
	}

	// Permitir inyectar la dirección de escucha por variable de entorno (ej. ":8080" para Docker o "127.0.0.1:8080" para local)
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080" // Valor por defecto seguro para desarrollo local
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	go func() {
		log.Printf("Remote Signer listening on http://%s", addr)

		if err := server.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			log.Printf("HTTP error: %v", err)
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	app.Shutdown()

	log.Println("Remote Signer stopped")
}
