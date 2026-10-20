package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/things-go/go-socks5/internal/gateway"
)

var version = "dev"

func main() {
	logger := log.New(os.Stderr, "cdesk-socks5: ", log.LstdFlags|log.LUTC)
	if err := run(logger); err != nil {
		logger.Print(err)
		os.Exit(1)
	}
}

func run(logger *log.Logger) error {
	path := flag.String("config", "config.json", "JSON configuration path")
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
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
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
