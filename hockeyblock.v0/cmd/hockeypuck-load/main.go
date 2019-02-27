package main

import (
	"flag"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/errgo.v1"
	"gopkg.in/hockeypuck/hkp.v1/sks"
	"gopkg.in/hockeypuck/hkp.v1/storage"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/hockeypuck/openpgp.v1"

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

	args := flag.Args()
	if len(args) == 0 {
		log.Errorf("usage: %s [flags] <file1> [file2 .. fileN]", os.Args[0])
		cmd.Die(errgo.New("missing PGP key file arguments"))
	}

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

	err = load(settings, flag.Args())
	cmd.Die(err)
}

func load(settings *server.Settings, args []string) error {
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

	statsFilename := sks.StatsFilename(settings.Conflux.Recon.LevelDB.Path)
	stats := sks.NewStats()
	err = stats.ReadFile(statsFilename)
	if err != nil {
		log.Warningf("failed to open stats file %q: %v", statsFilename, err)
		stats = sks.NewStats()
	}
	defer stats.WriteFile(statsFilename)

	st.Subscribe(func(kc storage.KeyChange) error {
		stats.Update(kc)
		ka, ok := kc.(storage.KeyAdded)
		if ok {
			digestZp, err := sks.DigestZp(ka.Digest)
			if err != nil {
				return errgo.Notef(err, "bad digest %q", ka.Digest)
			}
			return ptree.Insert(digestZp)
		}
		return nil
	})

	for _, arg := range args {
		matches, err := filepath.Glob(arg)
		if err != nil {
			log.Errorf("failed to match %q: %v", arg, err)
			continue
		}
		for _, file := range matches {
			f, err := os.Open(file)
			if err != nil {
				log.Errorf("failed to open %q for reading: %v", file, err)
			}
			var keys []*openpgp.PrimaryKey
			for kr := range openpgp.ReadKeys(f) {
				if kr.Error != nil {
					log.Errorf("error reading key: %v", errgo.Details(kr.Error))
				} else {
					keys = append(keys, kr.PrimaryKey)
				}
			}
			t := time.Now()
			n, err := st.Insert(keys)
			if err != nil {
				log.Errorf("some keys failed to insert from %q: %v", file, errgo.Details(err))
			}
			if n > 0 {
				log.Infof("inserted %d keys from %q in %v", n, file, time.Since(t))
			}
		}
	}

	return nil
}
