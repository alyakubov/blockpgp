package main

import (
	"flag"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/errgo.v1"

	/// AYAKU

	//"github.com/hockeypuck/server"
	//"github.com/hockeypuck/server/cmd"
	"github.com/alyakubov/blockpgp/hockeyblock.v0"
	"github.com/alyakubov/blockpgp/hockeyblock.v0/cmd"
	/// !AYAKU
)

var (
	configFile = flag.String("config", "", "config file")
	cpuProf    = flag.Bool("cpuprof", false, "enable CPU profiling")
	memProf    = flag.Bool("memprof", false, "enable mem profiling")
)

func main() {
	flag.Parse()

	var (
		settings *server.Settings
		err      error
	)
	if configFile != nil {
		conf, err := ioutil.ReadFile(*configFile)
		if err != nil {
			cmd.Die(errgo.Mask(err))
		}
		settings, err = server.ParseSettings(string(conf))
		if err != nil {
			cmd.Die(errgo.Mask(err))
		}
	}

	cpuFile := cmd.StartCPUProf(*cpuProf, nil)

	srv, err := server.NewServer(settings)
	if err != nil {
		cmd.Die(err)
	}

	srv.Start()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for {
			select {
			case sig := <-c:
				switch sig {
				case syscall.SIGINT, syscall.SIGTERM:
					srv.Stop()
				case syscall.SIGUSR1:
					srv.LogRotate()
				case syscall.SIGUSR2:
					cpuFile = cmd.StartCPUProf(*cpuProf, cpuFile)
					cmd.WriteMemProf(*memProf)
				}
			}
		}
	}()

	err = srv.Wait()
	cmd.Die(err)
}
