package services

import (
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

func ConfigureApplication(
	logger *logrus.Logger,
	appName string,
	defaultConfig map[string]interface{},
) (*koanf.Koanf, error) {
	f := pflag.NewFlagSet("config", pflag.ContinueOnError)
	f.Usage = func() {
		fmt.Println(f.FlagUsages())
		os.Exit(0)
	}
	f.StringSlice(
		"conf",
		[]string{fmt.Sprintf("%s.toml", strings.ToLower(appName))},
		"path to one or more .toml files",
	)
	var err error

	if err = f.Parse(os.Args[1:]); err != nil {
		logger.Fatal(err)
	}

	config := koanf.New(".")

	_ = config.Load(confmap.Provider(defaultConfig, "."), nil)
	cFiles, _ := f.GetStringSlice("conf")
	for _, c := range cFiles {
		if err := config.Load(file.Provider(c), toml.Parser()); err != nil {
			logger.Fatalf("error loading config file: %s", err)
		}
	}
	if err := config.Load(posflag.Provider(f, ".", config), nil); err != nil {
		logger.Fatalf("error loading configuration: %s", err)
	}
	if err := config.Load(
		file.Provider("resource_app.toml"),
		toml.Parser(),
	); err != nil && !os.IsNotExist(err) {
		logrus.Fatalf("error loading config: %v", err)
	}
	prefix := fmt.Sprintf("%s_", strings.ToUpper(appName))
	if err := config.Load(env.Provider(prefix, ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, prefix)), "_", ".", -1)
	}), nil); err != nil {
		logrus.Fatalf("error loading config: %v", err)
	}
	return config, err
}
