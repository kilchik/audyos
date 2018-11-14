package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

type config struct {
	Listen     string `toml:"listen"`
	DbUser     string `toml:"db_user"`
	DbPasswd   string `toml:"db_passwd"`
	DbName     string `toml:"db_name"`
	JwtSignKey string `toml:"jwt_sign_key"`
}

func readConfig(path string) (*config, error) {
	c := &config{}
	if _, err := toml.DecodeFile(path, c); err != nil {
		return nil, errors.Wrap(err, "decode config")
	}
	if err := c.validate(); err != nil {
		return nil, errors.Wrap(err, "validate config")
	}
	return c, nil
}

func (c *config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is not set in config")
	}
	if c.DbUser == "" {
		return fmt.Errorf("db_user is not set in config")
	}
	if c.DbPasswd == "" {
		return fmt.Errorf("db_passwd is not set in config")
	}
	if c.DbName == "" {
		return fmt.Errorf("db_name is not set in config")
	}
	return nil
}
