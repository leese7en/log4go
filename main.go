package main

import (
	"OPTest/const"
	"OPTest/log4go"
	"flag"
)

func main() {

	flag.Parse()
	defer log4go.Flush()
	flag.Set("log_dir", "logs")
	// flag.Set("alsologtostderr", "true")

	log4go.Infoln("Version:", opConst.Version)
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
