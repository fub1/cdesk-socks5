package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/things-go/go-socks5/internal/gateway"
)

var version = "dev"

func main() {
	os.Exit(execute())
}

func execute() int {
	logger := log.New(os.Stderr, "cdesk-socks5: ", log.LstdFlags|log.LUTC)
	if executable, err := os.Executable(); err == nil {
		logPath := filepath.Join(filepath.Dir(executable), "cdesk-socks5.log")
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			logger.Printf("WARN log_file_unavailable path=%q error=%q; using stderr", logPath, err.Error())
		} else {
			defer func() { _ = file.Close() }()
			logger.SetOutput(io.MultiWriter(file, os.Stderr))
			logger.Printf("INFO log_file path=%q timestamps=UTC", logPath)
		}
	} else {
		logger.Printf("WARN cannot locate executable for logging: %q; using stderr", err.Error())
	}
	if err := run(logger); err != nil {
		logger.Print(err)
		return 1
	}
	return 0
}

func run(logger *log.Logger) error {
	path := flag.String("config", "", "JSON configuration path (default: config.json beside the executable)")
	check := flag.Bool("check", false, "validate configuration and resolve allowed targets, then exit")
	showVersion := flag.Bool("version", false, "print build version")
	flag.Parse()
	if *showVersion {
		fmt.Println("cdesk-socks5", version)
		return nil
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *path == "" {
		executable, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate executable: %w", err)
		}
		*path = filepath.Join(filepath.Dir(executable), "config.json")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logger.Printf("INFO config path=%q", *path)
	cfg, err := gateway.Load(*path)
	if err != nil {
		return err
	}
	service, err := gateway.New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	if *check {
		logger.Print("configuration valid")
		return nil
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	logger.Printf("%s listening on %s (TCP CONNECT only)", version, listener.Addr())
	return service.Serve(ctx, listener)
}
