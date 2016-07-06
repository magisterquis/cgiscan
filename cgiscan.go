package main

/*
 * cgiscan.go
 * CGI program to synscan and banner the requestor
 * By J. Stuart McMurray
 * Created 20160704
 * Last Modified 20160705
 */

import (
	"container/list"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/boltdb/bolt"
)

/* Globals */
var (
	debug func(string, ...interface{}) /* Debug function */
	DB    *bolt.DB                     /* Scan database */
	START = time.Now()                 /* Server start time */
)

/* qaddr is an address waiting in the queue, with the time it went in */
type qaddr struct {
	a string
	t time.Time
}

/* newQaddr makes a qaddr with a time of now */
func newQaddr(a string) qaddr { return qaddr{a: a, t: time.Now()} }

func init() {
	SCANNING = make(map[string]time.Time)
	QUEUE = list.New()
	QLOCK = &sync.Mutex{}
	QCOND = sync.NewCond(QLOCK)
	AVGLOCK = &sync.Mutex{}
}

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
	http.HandleFunc(*path, handleScan)
	http.HandleFunc(*path+"/query", query)

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
		log.Printf("Listening on standard i/o")
	} else if *tcp {
		l, err = net.Listen("tcp", *sock)
	} else { /* Unix */
		l, err = listenUnix(*sock, 0600)
	}
	if nil != err {
		log.Fatalf("Unable to listen on %v: %v", *sock, err)
	}
	if "-" == *sock {
		log.Printf("Listening on stdio")
	} else {
		log.Printf("Listening on %v", l.Addr())
	}

	/* Start scanner */
	go scanner(*nAttempt)

	/* Serve up scans */
	if err := fcgi.Serve(l, nil); nil != err {
		log.Fatalf("Error: %v", err)
	}
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

/* TODO: Max queue length */
