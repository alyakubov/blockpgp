/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package server

import (
	"github.com/BurntSushi/toml"
	"gopkg.in/errgo.v1"

	"gopkg.in/hockeypuck/conflux.v2/recon"
)

type confluxConfig struct {
	Recon reconConfig `toml:"recon"`
}

type levelDB struct {
	Path string `toml:"path"`
}

type reconConfig struct {
	recon.Settings
	LevelDB levelDB `toml:"leveldb"`
}

const (
	DefaultHKPBind = ":11371"
)

type HKPConfig struct {
	Bind string `toml:"bind"`
}

type HKPSConfig struct {
	HKPConfig
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

type PKSConfig struct {
	From string     `toml:"from"`
	To   []string   `toml:"to"`
	SMTP SMTPConfig `toml:"smtp"`
}

const (
	DefaultSMTPHost = "localhost:25"
)

type SMTPConfig struct {
	Host     string `toml:"host"`
	ID       string `toml:"id"`
	User     string `toml:"user"`
	Password string `toml:"pass"`
}

const (
	DefaultDBDriver = "mongo"
	DefaultDBDSN    = "localhost:27017"
)

type DBConfig struct {
	Driver string       `toml:"driver"`
	DSN    string       `toml:"dsn"`
	Mongo  *mongoConfig `toml:"mongo"`
}

type mongoConfig struct {
	DB         string `toml:"db"`
	Collection string `toml:"collection"`
}

const (
	DefaultStatsRefreshHours = 4
	DefaultNWorkers          = 8
)

type OpenPGPConfig struct {
	PKS      *PKSConfig `toml:"pks"`
	NWorkers int        `toml:"nworkers"`
	DB       DBConfig   `toml:"db"`
}

func DefaultOpenPGP() OpenPGPConfig {
	return OpenPGPConfig{
		NWorkers: DefaultNWorkers,
		DB: DBConfig{
			Driver: DefaultDBDriver,
			DSN:    DefaultDBDSN,
		},
	}
}

type Settings struct {
	Conflux confluxConfig `toml:"conflux"`

	IndexTemplate  string `toml:"indexTemplate"`
	VIndexTemplate string `toml:"vindexTemplate"`
	StatsTemplate  string `toml:"statsTemplate"`

	HKP  HKPConfig   `toml:"hkp"`
	HKPS *HKPSConfig `toml:"hkps"`

	OpenPGP OpenPGPConfig `toml:"openpgp"`

	LogFile  string `toml:"logfile"`
	LogLevel string `toml:"loglevel"`

	Webroot string `toml:"webroot"`

	Contact  string `toml:"contact"`
	Hostname string `toml:"hostname"`
	Software string `toml:"software"`
	Version  string `toml:"version"`
}

const (
	DefaultLogLevel    = "INFO"
	DefaultLevelDBPath = "recon.db"
)

func DefaultSettings() Settings {
	reconSettings := recon.DefaultSettings()
	return Settings{
		Conflux: confluxConfig{
			Recon: reconConfig{
				Settings: *reconSettings,
				LevelDB: levelDB{
					Path: DefaultLevelDBPath,
				},
			},
		},
		HKP: HKPConfig{
			Bind: DefaultHKPBind,
		},
		OpenPGP:  DefaultOpenPGP(),
		LogLevel: DefaultLogLevel,
		Software: "Hockeypuck",
		Version:  "~unreleased",
	}
}

func ParseSettings(data string) (*Settings, error) {
	var doc struct {
		Hockeypuck Settings `toml:"hockeypuck"`
	}
	doc.Hockeypuck = DefaultSettings()
	_, err := toml.Decode(data, &doc)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	err = doc.Hockeypuck.Conflux.Recon.Settings.Resolve()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return &doc.Hockeypuck, nil
}
