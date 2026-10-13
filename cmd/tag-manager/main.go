package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/pelletier/go-toml/v2"

	"github.com/dnstapir/tapir-analyse-lib/common"
	"github.com/dnstapir/tapir-analyse-lib/logger"
	"github.com/dnstapir/tapir-analyse-lib/nats"

	"github.com/dnstapir/tag-manager/internal/api"
	"github.com/dnstapir/tag-manager/internal/app"
)

const env_DNSTAPIR_NATS_URL = "DNSTAPIR_NATS_URL"

const c_ANALYST_IDENTIFIER = "tag-manager"

/* Rewritten if building with make */
var commit = "BAD-BUILD"

type conf struct {
	app.Conf
	Api  api.Conf  `toml:"api"`
	Nats nats.Conf `toml:"nats"`
}

func main() {
	var configFile string
	var runVersionCmd bool
	var debugFlag bool
	var mainConf conf

	flag.BoolVar(&runVersionCmd,
		"version",
		false,
		"Print version then exit",
	)
	flag.StringVar(&configFile,
		"config",
		"config.toml",
		"Configuration file to use",
	)
	flag.BoolVar(&debugFlag,
		"debug",
		false,
		"Enable DEBUG logs",
	)
	flag.Parse()

	log := logger.New(
		logger.Conf{
			Debug: debugFlag,
		})

	log.Info("%s, commit: '%s'", c_ANALYST_IDENTIFIER, commit)
	if runVersionCmd {
		os.Exit(0)
	}

	if configFile == "" {
		log.Error("No config file specified, exiting...")
		os.Exit(-1)
	}

	file, err := os.Open(configFile)
	if err != nil {
		log.Error("Couldn't open config file '%s', exiting...", configFile)
		os.Exit(-1)
	}
	defer file.Close()

	confDecoder := toml.NewDecoder(file)
	if confDecoder == nil {
		log.Error("Problem creating decoder for config file '%s', exiting...", configFile)
		os.Exit(-1)
	}

	confDecoder.DisallowUnknownFields()
	err = confDecoder.Decode(&mainConf)
	if err != nil {
		log.Error("Problem decoding config file '%s': %s", configFile, err)
		os.Exit(-1)
	}

	debugFlag = debugFlag || mainConf.Debug

	mainConf.AnalystID = c_ANALYST_IDENTIFIER
	mainConf.Nats.AnalystID = c_ANALYST_IDENTIFIER

	/*
	 ******************************************************************
	 ********************** SET UP NATS *******************************
	 ******************************************************************
	 */
	natslog := logger.New(
		logger.Conf{
			Debug: debugFlag || mainConf.Nats.Debug,
		})

	envNatsUrl, overrideNatsUrl := os.LookupEnv(env_DNSTAPIR_NATS_URL)
	if overrideNatsUrl {
		mainConf.Nats.Url = envNatsUrl
		log.Info("Overriding NATS url with environment variable '%s'", env_DNSTAPIR_NATS_URL)
	}

	mainConf.Nats.Log = natslog
	natsHandle, err := nats.Create(mainConf.Nats)
	if err != nil {
		log.Error("Could not create NATS handle: %s", err)
		os.Exit(-1)
	}

	/*
	 ******************************************************************
	 ********************** SET UP MAIN APP ***************************
	 ******************************************************************
	 */
	applog := logger.New(
		logger.Conf{
			Debug: debugFlag || mainConf.Debug,
		})
	mainConf.Log = applog
	mainConf.NatsHandle = natsHandle
	appHandle, err := app.Create(mainConf.Conf)
	if err != nil {
		log.Error("Error creating application: '%s'", err)
		os.Exit(-1)
	}

	/*
	 ******************************************************************
	 ********************** SET UP API ********************************
	 ******************************************************************
	 */
	apilog := logger.New(
		logger.Conf{
			Debug: debugFlag || mainConf.Api.Debug,
		})
	mainConf.Api.Log = apilog
	mainConf.Api.App = appHandle
	apiHandle, err := api.Create(mainConf.Api)
	if err != nil {
		log.Error("Error creating API: '%s'", err)
		os.Exit(-1)
	}

	/*
	 ******************************************************************
	 ********************** START RUNNING STUFF ***********************
	 ******************************************************************
	 */
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer close(sigChan)
	defer signal.Stop(sigChan)

	ctx, cancel := context.WithCancel(context.Background())
	exitCh := make(chan common.Exit, 10)

	log.Info("Starting threads...")

	var wg sync.WaitGroup
	wg.Go(func() { appHandle.Run(ctx, exitCh) })
	wg.Go(func() { apiHandle.Run(ctx, exitCh) })

	log.Info("Threads started!")

	exitLoop := false
	for {
		select {
		case s, ok := <-sigChan:
			if ok {
				log.Info("Got signal '%s'", s)
				exitLoop = true
			} else {
				log.Info("signal channel was closed")
				sigChan = nil
			}
		case exit, ok := <-exitCh:
			if ok {
				if exit.Err != nil {
					log.Error("%s exited with error: '%s'", exit.ID, exit.Err)
					if exit.Err == common.ErrFatal {
						exitLoop = true
					}
				} else {
					log.Info("%s done!", exit.ID)
				}
			} else {
				log.Warning("exit channel closed unexpectedly")
				exitCh = nil
			}
		}
		if exitLoop || (sigChan == nil && exitCh == nil) {
			log.Info("Leaving toplevel loop")
			break
		}
	}

	log.Info("Cancelling threads")
	cancel()

	log.Info("Waiting for threads to finish")
	wg.Wait()
	log.Info("Exiting...")
	os.Exit(0)
}
