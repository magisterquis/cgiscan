package main

/*
 * cgiscan.go
 * CGI program to synscan and banner the requestor
 * By J. Stuart McMurray
 * Created 20160704
 * Last Modified 20160708
 */

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"path/filepath"
	"time"

	"github.com/boltdb/bolt"
)

/* Globals */
const RESBUCKET = "Results" /* Bucket name for results */
var (
	debug   func(string, ...interface{}) /* Debug function */
	DB      *bolt.DB                     /* Scan database */
	START   = time.Now()                 /* Server start time */
	URLPATH string                       /* Leading bit of URL */
)

func main() {
	var (
		path = flag.String(
			"p",
			"/cgiscan",
			"URL `path` to which to respond",
		)
		sock = flag.String(
			"s",
			"/run/cgiscan/cgiscan.sock",
			"Address or `path` to listen for FastCGI "+
				"connections; may be \"-\" for stdio",
		)
		tcp = flag.Bool(
			"t",
			false,
			"Listen on a TCP socket and treat -s as an address",
		)
		debugOn = flag.Bool(
			"d",
			false,
			"Print debugging messages",
		)
		dbFile = flag.String(
			"db",
			"/run/cgiscan/cgiscan.db",
			"Database `file`",
		)
		nAttempt = flag.Uint(
			"n",
			128,
			"Scan `count` ports in parallel",
		)
		serveHTTPS = flag.Bool(
			"https",
			false,
			"Serve HTTPS instead of FastCGI",
		)
		certFile = flag.String(
			"cert",
			"cert.pem",
			"TLS cert used if -https is given",
		)
		keyFile = flag.String(
			"key",
			"key.pem",
			"TLS key used if -https is given",
		)
		qsockPath = flag.String(
			"q",
			"",
			"Unix domain socket path for local queuing",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Listens for FastCGI connections to serve up a scanning service.

Options:
`, os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Turn on/off logging */
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix(fmt.Sprintf(
		"%v[%v]: ",
		filepath.Base(os.Args[0]),
		os.Getpid(),
	))
	if *debugOn {
		debug = log.Printf
	} else {
		debug = func(string, ...interface{}) {}
	}

	/* Register handlers */
	if "/" == *path {
		http.HandleFunc("/", status)
	} else {
		URLPATH = *path
		http.HandleFunc(URLPATH, status)
	}
	http.HandleFunc(URLPATH+"/status", status)
	http.HandleFunc(URLPATH+"/scan", handleScan)
	http.HandleFunc(URLPATH+"/res/", query)
	http.HandleFunc(URLPATH+"/list", listScanned)
	http.HandleFunc(URLPATH+"/delete", deleteResult)
	http.HandleFunc(URLPATH+"/help", help)
	http.HandleFunc(URLPATH+"/queue", sendQueue)

	/* Open Database */
	var err error
	DB, err = bolt.Open(*dbFile, 0600, nil)
	if nil != err {
		log.Fatalf("Unable to open database %v: %v", *dbFile, err)
	}

	/* Make sure we have a bucket in the database */
	bn := []byte(RESBUCKET)
	DB.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bn)
		return err
	})
	if err != nil {
		log.Fatalf(
			"Unable to create bucket %s in database: %v",
			bn,
			err,
		)
	}

	/* Listen for FastCGI connections */
	var l net.Listener
	if "-" == *sock {
		if *serveHTTPS {
			log.Fatalf("Can't serve https via stdio")
		}
		log.Printf("Listening on standard i/o")
	} else if *tcp {
		l, err = net.Listen("tcp", *sock)
	} else { /* Unix */
		l, err = listenUnix(*sock, 0600)
	}
	if nil != err {
		log.Fatalf("Unable to listen on %v: %v", *sock, err)
	}
	if nil != l {
		log.Printf("Listening on %v", l.Addr())
	}

	/* Maybe listen for local queues, as well */
	if "" != *qsockPath {
		go qsock(*qsockPath)
	}

	/* Start scanner */
	go scanner(*nAttempt)

	/* Serve up HTTPS or FastCGI */
	if *serveHTTPS {
		err = https(l, *certFile, *keyFile)
	} else {
		err = fcgi.Serve(l, nil)
	}

	/* Tell the user we're done.  This shouldn't happen much */
	if nil != err {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("Done.  This is a bug.")
}

/* ListenUnix tries to listen on a unix socket.  If successful, it sets the
permissions of the socket to perm.  The socket will be removed if it exists. */
func listenUnix(path string, perm os.FileMode) (net.Listener, error) {
	/* Remove the socket if it exists */
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); nil != err {
			return nil, err
		}
	}
	/* Listen on the socket */
	l, err := net.Listen("unix", path)
	if nil != err {
		return nil, err
	}
	/* Change file permissions */
	if err := os.Chmod(path, perm); nil != err {
		return nil, err
	}

	return l, nil
}

/* https serves up HTTPS responses, as opposed to FCGI */
func https(l net.Listener, certFile, keyFile string) error {
	/* Load cert and key */
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if nil != err {
		return err
	}

	/* Upgrade listener to a TLS'd listener */
	tl := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})

	return http.Serve(tl, nil)
}

/* TODO: Max queue length */
