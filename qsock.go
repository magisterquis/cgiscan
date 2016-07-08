package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

/*
 * qsock.go
 * Listen for manual queuing
 * By J. Stuart McMurray
 * Created 20160708
 * Last Modified 20160708
 */

/* qsock listens on a unix socket for IP addresses, and if it gets one, it
queues it up for scanning */
func qsock(path string) {
	/* Remove socket if it exists */
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); nil != err {
			log.Fatalf("ERROR: Unable to remove %v: %v", path, err)
		}
	}

	/* Listen on the socket */
	l, err := net.Listen("unix", path)
	if nil != err {
		log.Fatalf("ERROR: Unable to listen on %v: %v", path, err)
	}
	log.Printf("Listening for local queue requests on %v", l.Addr())

	/* Handle requests */
	for {
		c, err := l.Accept()
		if nil != err {
			log.Fatalf(
				"ERROR: Unable to accept clients on %v: %v",
				l.Addr(),
				err,
			)
		}
		go handleQSock(c)
	}
}

/* handleQSock handles a local queue request */
func handleQSock(c net.Conn) {
	defer c.Close()

	/* Requests should be one line only */
	l, err := bufio.NewReader(c).ReadString('\n')
	if nil != err {
		debug(
			"<Unix Socket> Unable to read local queue request: %v",
			err,
		)
		c.Write([]byte(fmt.Sprintf("%v\n", err)))
		return
	}
	l = strings.TrimSpace(strings.ToLower(l))

	/* Make sure the IP is an IP */
	if nil == net.ParseIP(l) {
		io.WriteString(c, "Invalid address.\n")
		debug("<Unix Socket> Invalid address %q", l)
		return
	}

	enqueue(l)
	debug("<Unix Socket> Queued %v", l)
	io.WriteString(c, "Ok.\n")
}
