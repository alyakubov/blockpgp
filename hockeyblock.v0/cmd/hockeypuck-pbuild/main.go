package main

import (
	"flag"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/hkp.v1/sks"
	"gopkg.in/hockeypuck/hkp.v1/storage"
	log "gopkg.in/hockeypuck/logrus.v0"

	"github.com/hockeypuck/server"
	"github.com/hockeypuck/server/cmd"
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

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGUSR2)
	go func() {
		for {
			select {
			case sig := <-c:
				switch sig {
				case syscall.SIGUSR2:
					cpuFile = cmd.StartCPUProf(*cpuProf, cpuFile)
					cmd.WriteMemProf(*memProf)
				}
			}
		}
	}()

	err = pbuild(settings)
	cmd.Die(err)
}

func pbuild(settings *server.Settings) error {
	st, err := server.DialStorage(settings)
	if err != nil {
		return errgo.Mask(err)
	}
	defer st.Close()

	ptree, err := sks.NewPrefixTree(settings.Conflux.Recon.LevelDB.Path, &settings.Conflux.Recon.Settings)
	if err != nil {
		return errgo.Mask(err)
	}
	err = ptree.Create()
	if err != nil {
		return errgo.Mask(err)
	}
	defer ptree.Close()

	stats := sks.NewStats()

	var n int
	st.Subscribe(func(kc storage.KeyChange) error {
		ka, ok := kc.(storage.KeyAdded)
		if ok {
			digestZp, err := sks.DigestZp(ka.Digest)
			if err != nil {
				return errgo.Notef(err, "bad digest %q", ka.Digest)
			}
			err = ptree.Insert(digestZp)
			if err != nil {
				return errgo.Notef(err, "failed to insert digest %q", ka.Digest)
			}

			stats.Update(kc)

			n++
			if n%5000 == 0 {
				log.Infof("%d keys added", n)
			}
		}
		return nil
	})

	defer func() {
		err := stats.WriteFile(sks.StatsFilename(settings.Conflux.Recon.LevelDB.Path))
		if err != nil {
			log.Warningf("error writing stats: %v", err)
		}
	}()
	err = st.RenotifyAll()
	return errgo.Mask(err)
}
