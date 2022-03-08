package main

import (
	"github.com/sirupsen/logrus"
	"github.com/jandubois/resolved/pkg/dns"
)

func main() {
	srv, err := dns.Start("127.0.0.53", 53, 53, false, map[string]string{})
	if err != nil {
		return
	}
	logrus.Infof("Started srv %+v", srv)
	for {
	}
}
