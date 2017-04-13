package log4go

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type Config struct {
	filepath string
	conflist map[string]string
}

//Create an empty configuration file
func SetConfig(filepath string) (*Config, error) {
	c := new(Config)
	c.filepath = filepath
	_, err := os.Stat(filepath)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) GetConfig() (map[string]string, error) {
	return c.ReadList()
}

func (c *Config) GetValue(name string) string {
	c.ReadList()
	return c.conflist[name]
}

func (c *Config) SetValue(key, value string) bool {
	c.ReadList()
	c.conflist[key] = value
	return true

}

func (c *Config) DeleteValue(name string) bool {
	c.ReadList()
	delete(c.conflist, name)
	return true
}

func (c *Config) ReadList() (map[string]string, error) {
	file, err := os.Open(c.filepath)
	if err != nil {
		fmt.Println("open file error:", err)
		return nil, err
	}
	defer file.Close()
	var data map[string]string
	data = make(map[string]string)
	buf := bufio.NewReader(file)
	for {
		l, err := buf.ReadString('\n')
		line := strings.TrimSpace(l)
		if err != nil {
			if err != io.EOF {
				CheckErr(err)
			}
			if len(line) == 0 {
				break
			}
		}
		switch {
		case len(line) == 0:
		case string(line[0]) == "#":
		default:
			i := strings.IndexAny(line, "=")
			value := strings.TrimSpace(line[i+1 : len(line)])
			key := strings.TrimSpace(line[:i-1])
			if c.uniquappend(key) == true {
				data[key] = value
			}
		}
	}
	c.conflist = data
	return c.conflist, nil
}

func CheckErr(err error) string {
	if err != nil {
		return fmt.Sprintf("Error is :'%s'", err.Error())
	}
	return "Notfound this error"
}

func (c *Config) uniquappend(conf string) bool {
	for _, v := range c.conflist {
		if v == conf {
			return false
		}
	}
	return true
}
