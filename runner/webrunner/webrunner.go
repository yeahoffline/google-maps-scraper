package webrunner

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gosom/google-maps-scraper/runner"
	"github.com/gosom/google-maps-scraper/tlmt"
	"github.com/gosom/google-maps-scraper/web"
	"github.com/gosom/google-maps-scraper/web/sqlite"
	"github.com/gosom/scrapemate"
	"github.com/gosom/scrapemate/adapters/writers/csvwriter"
	"github.com/gosom/scrapemate/scrapemateapp"
	"golang.org/x/sync/errgroup"
)

type webrunner struct {
	srv *web.Server
	svc *web.Service
	cfg *runner.Config
}

func New(cfg *runner.Config) (runner.Runner, error) {
	if cfg.DataFolder == "" {
		return nil, fmt.Errorf("data folder is required")
	}

	if err := os.MkdirAll(cfg.DataFolder, os.ModePerm); err != nil {
		return nil, err
	}

	const dbfname = "jobs.db"

	dbpath := filepath.Join(cfg.DataFolder, dbfname)

	repo, err := sqlite.New(dbpath)
	if err != nil {
		return nil, err
	}

	svc := web.NewService(repo, cfg.DataFolder)

	srv, err := web.New(svc)
	if err != nil {
		return nil, err
	}

	ans := webrunner{
		srv: srv,
		svc: svc,
		cfg: cfg,
	}

	return &ans, nil
}

func (w *webrunner) Run(ctx context.Context) error {
	egroup, ctx := errgroup.WithContext(ctx)

	egroup.Go(func() error {
		return w.work(ctx)
	})

	egroup.Go(func() error {
		return w.srv.Start(ctx)
	})

	return egroup.Wait()
}

func (w *webrunner) Close(ctx context.Context) error {
	var errs []error
	
	// Close the server if it exists
	if w.srv != nil {
		if err := w.srv.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close server: %w", err))
		}
	}

	// Close the service if it exists
	if w.svc != nil {
		if err := w.svc.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close service: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during cleanup: %v", errs)
	}
	return nil
}

func (w *webrunner) work(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			jobs, err := w.svc.SelectPending(ctx)
			if err != nil {
				return err
			}

			for i := range jobs {
				select {
				case <-ctx.Done():
					return nil
				default:
					t0 := time.Now().UTC()
					if err := w.scrapeJob(ctx, &jobs[i]); err != nil {
						params := map[string]any{
							"job_count": len(jobs[i].Data.Keywords),
							"duration":  time.Now().UTC().Sub(t0).String(),
							"error":     err.Error(),
						}

						evt := tlmt.NewEvent("web_runner", params)

						_ = runner.Telemetry().Send(ctx, evt)

						log.Printf("error scraping job %s: %v", jobs[i].ID, err)
					} else {
						params := map[string]any{
							"job_count": len(jobs[i].Data.Keywords),
							"duration":  time.Now().UTC().Sub(t0).String(),
						}

						_ = runner.Telemetry().Send(ctx, tlmt.NewEvent("web_runner", params))

						log.Printf("job %s scraped successfully", jobs[i].ID)
					}
				}
			}
		}
	}
}

func (w *webrunner) scrapeJob(ctx context.Context, job *web.Job) error {
	job.Status = web.StatusWorking

	if err := w.svc.Update(ctx, job); err != nil {
		return fmt.Errorf("failed to update job status: %w", err)
	}

	if len(job.Data.Keywords) == 0 {
		job.Status = web.StatusFailed
		return w.svc.Update(ctx, job)
	}

	outpath := filepath.Join(w.cfg.DataFolder, job.ID+".csv")
	outfile, err := os.Create(outpath)
	if err != nil {
		job.Status = web.StatusFailed
		if updateErr := w.svc.Update(ctx, job); updateErr != nil {
			return fmt.Errorf("failed to create output file: %v and update status: %v", err, updateErr)
		}
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		if closeErr := outfile.Close(); closeErr != nil {
			log.Printf("error closing output file: %v", closeErr)
		}
	}()

	mate, err := w.setupMate(ctx, outfile)
	if err != nil {
		job.Status = web.StatusFailed
		if updateErr := w.svc.Update(ctx, job); updateErr != nil {
			return fmt.Errorf("failed to setup mate: %v and update status: %v", err, updateErr)
		}
		return fmt.Errorf("failed to setup mate: %w", err)
	}
	
	// Ensure mate is always closed
	defer func() {
		if mate != nil {
			mate.Close()
		}
	}()

	var coords string
	if job.Data.Lat != "" && job.Data.Lon != "" {
		coords = job.Data.Lat + "," + job.Data.Lon
	}

	seedJobs, err := runner.CreateSeedJobs(
		job.Data.Lang,
		strings.NewReader(strings.Join(job.Data.Keywords, "\n")),
		job.Data.Depth,
		job.Data.Email,
		coords,
		job.Data.Zoom,
	)
	if err != nil {
		job.Status = web.StatusFailed
		if updateErr := w.svc.Update(ctx, job); updateErr != nil {
			return fmt.Errorf("failed to create seed jobs: %v and update status: %v", err, updateErr)
		}
		return fmt.Errorf("failed to create seed jobs: %w", err)
	}

	if len(seedJobs) > 0 {
		allowedSeconds := max(60, len(seedJobs)*10*job.Data.Depth/50+120)

		if job.Data.MaxTime > 0 {
			if job.Data.MaxTime.Seconds() < 60 {
				allowedSeconds = 60
			} else {
				allowedSeconds = int(job.Data.MaxTime.Seconds())
			}
		}

		log.Printf("running job %s with %d seed jobs and %d allowed seconds", job.ID, len(seedJobs), allowedSeconds)

		mateCtx, cancel := context.WithTimeout(ctx, time.Duration(allowedSeconds)*time.Second)
		defer cancel()

		err = mate.Start(mateCtx, seedJobs...)
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			job.Status = web.StatusFailed
			if updateErr := w.svc.Update(ctx, job); updateErr != nil {
				return fmt.Errorf("failed to run mate: %v and update status: %v", err, updateErr)
			}
			return fmt.Errorf("failed to run mate: %w", err)
		}
	}

	job.Status = web.StatusOK
	return w.svc.Update(ctx, job)
}

func (w *webrunner) setupMate(ctx context.Context, writer io.Writer) (*scrapemateapp.ScrapeMateApp, error) {
	opts := []func(*scrapemateapp.Config) error{
		scrapemateapp.WithConcurrency(w.cfg.Concurrency),
		scrapemateapp.WithJS(scrapemateapp.DisableImages()),
		scrapemateapp.WithExitOnInactivity(w.cfg.ExitOnInactivityDuration),
		scrapemateapp.WithJS(scrapemateapp.WithBrowserCleanupTimeout(time.Second * 5)),
		scrapemateapp.WithJS(scrapemateapp.WithForceCleanup()),
		scrapemateapp.WithJS(scrapemateapp.WithNavigationTimeout(time.Second * 12)),
		scrapemateapp.WithJS(scrapemateapp.WithBrowserArgs([]string{
			"--disable-dev-shm-usage",
			"--disable-gpu",
			"--no-sandbox",
			"--js-flags=--max-old-space-size=512",
		})),
	}

	csvWriter := csvwriter.NewCsvWriter(csv.NewWriter(writer))
	// Ensure writer is flushed after each write
	csvWriter.AutoFlush(true)

	writers := []scrapemate.ResultWriter{csvWriter}

	matecfg, err := scrapemateapp.NewConfig(
		writers,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create scrapemate config: %w", err)
	}

	app, err := scrapemateapp.NewScrapeMateApp(matecfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create scrapemate app: %w", err)
	}

	// Add cleanup on context cancellation
	go func() {
		<-ctx.Done()
		if app != nil {
			app.Close()
		}
	}()

	return app, nil
}
