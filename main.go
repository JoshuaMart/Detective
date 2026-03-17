package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/jomar/recon/config"
	"github.com/jomar/recon/pipeline"
	"github.com/jomar/recon/push"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel(),
	})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.JobTimeout)
	defer cancel()

	client := push.NewClient(cfg.APIURL, cfg.IngestAPIKey)
	updateJobStatus(client, cfg.JobID, "running")

	if err := pipeline.Run(ctx, cfg, client); err != nil {
		slog.Error("pipeline failed", "error", err)
		updateJobStatus(client, cfg.JobID, "failed")
		os.Exit(1)
	}

	updateJobStatus(client, cfg.JobID, "completed")
}

// updateJobStatus uses a fresh context to ensure the status update goes through
// even if the pipeline context has timed out.
func updateJobStatus(client *push.Client, jobID, status string) {
	statusCtx, statusCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer statusCancel()

	if err := client.UpdateJobStatus(statusCtx, jobID, status); err != nil {
		slog.Error("failed to update job status", "error", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	if os.Getenv("LOG_LEVEL") == "debug" {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
