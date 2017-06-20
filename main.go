package main

import (
	"OPTest/log4go"
	"flag"
)

func main() {

	flag.Parse()
	defer log4go.Flush()
	i := 0
	for i < 2000 {
		log4go.Info("Agent info:", i)
		log4go.Debug("Agent debug:", i)
		log4go.Warning("Agent waring.")
		log4go.Error("Agent error:", i)
		i++
	}
	log4go.Info("Agent stopped.")
}
