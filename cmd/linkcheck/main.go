// Command linkcheck serves the inspection API, the API documentation and
// the built frontend from a single binary.
package main

import (
	"net/http"
	"os"
	"time"

	elog "github.com/eluv-io/log-go"

	"github.com/moritzanliker/link-inspector/inspect"
	"github.com/moritzanliker/link-inspector/internal/server"
)

var log = elog.Get("/link-inspector")

func main() {
	ins := inspect.NewInspector(inspect.NewFollower(inspect.NewGuard()))
	handler := server.New(ins, "web/dist")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("listening", "port", port)
	log.Fatal("server stopped", srv.ListenAndServe())
}
