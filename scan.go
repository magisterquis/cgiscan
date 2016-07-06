package main

/*
 * scan.go
 * Scan a requestor
 * By J. Stuart McMurray
 * Created 20160706
 * Last Modified 20160706
 */

import (
	"bytes"
	"container/list"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
)

/* portRes is the result of scanning an open port */
type portRes struct {
	port   int
	banner []byte
}

/* qaddr is an address waiting in the queue, with the time it went in */
type qaddr struct {
	a string
	t time.Time
}

/* newQaddr makes a qaddr with a time of now */
func newQaddr(a string) qaddr { return qaddr{a: a, t: time.Now()} }

const ()

/* Target queue */
var (
	QUEUE    *list.List           /* Scan queue */
	SCANNING map[string]time.Time /* Scans in progress */
	QLOCK    *sync.Mutex          /* Lock for QUEUE */
	QCOND    *sync.Cond           /* Notifier for queue adds */
)

/* Maintain the average time of each scan */
var (
	NSCAN   int           /* Number scanned */
	AVGTIME time.Duration /* Average scan time */
	AVGLOCK *sync.Mutex   /* Average scan time lock */
	/* TODO: Use NSCAN and AVGTIME */
)

func init() {
	SCANNING = make(map[string]time.Time)
	QUEUE = list.New()
	QLOCK = &sync.Mutex{}
	QCOND = sync.NewCond(QLOCK)
	AVGLOCK = &sync.Mutex{}
}

/* scan Scans an IP address */
func scan(a string, nAttempt uint, start time.Time) []byte {
	debug("%v Scanning", a)
	/* Open ports */
	var successes = make(map[int][]byte)

	/* Port Scanners */
	var wg sync.WaitGroup
	ps := make(chan int)
	os := make(chan portRes)
	wg.Add(int(nAttempt))
	for i := 0; i < int(nAttempt); i++ {
		go scanPorts(a, ps, os, &wg)
	}

	/* Send ports to scanners */
	for i := 1; i <= 65535; i++ {
		ps <- i
		if 0 == i%10000 {
			debug(
				"%v Queued port %v (%v)",
				a,
				i,
				time.Now().Sub(start),
			)
		}
	}
	close(ps)

	/* Receive scanners' output, put in successes */
	sdone := make(chan struct{})
	go func() {
		for o := range os {
			successes[o.port] = o.banner
		}
		close(sdone)
	}()

	/* Wait for scanners to finish */
	wg.Wait()
	close(os)

	/* Wait for receiver to finish */
	<-sdone

	sd := time.Now().Sub(start) /* Scan duration */
	debug("%v Scanned in %v", a, sd)

	/* Maintain averages */
	updateAverages(sd)

	/* Craft and return result */
	return openPortsReport(successes, start)
}

/* scanPort scans the ports on a it gets from ps, and reports to os */
func scanPorts(a string, ps <-chan int, os chan<- portRes, wg *sync.WaitGroup) {
	defer wg.Done()
	for p := range ps {
		var (
			b   []byte
			err error
		)
	try:
		/* Attack the single port */
		b, err = tryPort(a, p)
		if nil != err {
			/* This means we're trying too hard, retry in a bit */
			if strings.HasSuffix(
				err.Error(),
				"connect: no route to host",
			) {
				time.Sleep(time.Second)
				goto try
			}
			/* Port's not open, try the next one */
			continue
		}
		/* Port's open, return the banner */
		os <- portRes{port: p, banner: b}
	}
}

/* tryPort tries a single address and port, and returns the banner */
func tryPort(a string, p int) ([]byte, error) {
	c, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort(a, strconv.Itoa(p)),
		time.Second, /* TODO: unhardcode this */
	)
	if nil != err {
		return nil, err
	}
	defer c.Close()
	/* Banner-grab */
	b := make([]byte, 128) /* TODO: unhardcode this */
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); nil != err {
		/* And that ^^ */
		return nil, nil
	}
	n, _ := c.Read(b)
	/* A nil buffer means no banner */
	if 0 == n {
		return nil, nil
	}
	/* Shrink the buffer to what we got, return it */
	b = b[:n]
	return b, nil
}

/* openPortsReport makes a nice report from the set of open ports and the
start time of the scan. */
func openPortsReport(m map[int][]byte, start time.Time) []byte {
	/* Report to be returned */
	report := &bytes.Buffer{}
	fmt.Fprintf(
		report,
		"Scan finished at %v\n\n",
		time.Now().UTC().Format(time.RFC3339),
	)

	/* No ports is an easy case */
	if 0 == len(m) {
		fmt.Fprintf(report, "No ports open.\n\n")
		return report.Bytes()
	}

	/* Sorted open ports list */
	os := make([]int, 0, len(m))
	for k := range m {
		os = append(os, k)
	}
	sort.Ints(os)

	/* Header */
	fmt.Fprintf(report, "Port   | Banner\n")
	fmt.Fprintf(report, "-------+-------\n")

	/* Add each port to the list */
	for _, o := range os {
		var banner string
		/* Print banner */
		if nil == m[o] || 0 == len(m[o]) {
			banner = "None"
		} else {
			banner = fmt.Sprintf("%q", m[o])
		}
		/* Add to report */
		fmt.Fprintf(report, "%-6v | %v\n", o, banner)
	}

	return report.Bytes()
}

/* handle handles incoming scan requests */
func handleScan(w http.ResponseWriter, req *http.Request) {
	/* Get the requestor's address */
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}

	/* Queue it up */
	enqueue(ip)

	/* Redirect back */
	http.Redirect(w, req, URLPATH, http.StatusSeeOther)
}

/* enqueue adds the address to the scan queue if it's not already there (or
being scanned */
func enqueue(a string) {
	/* Make sure we're not currently scanning */
	if st, ok := SCANNING[a]; ok {
		debug("%v Being scanned")
		return
	}
	/* Make sure we're not in the queue */
	pos := 1
	for e := QUEUE.Front(); nil != e; e = e.Next() {
		q := e.Value.(qaddr)
		/* If we are, report the position */
		if q.a == a {
			debug("%v In queue, position %v", a, pos)
			return
		}
		pos++
	}
	/* Add to the list */
	/* This whole thing should probably be replaced by a circular buffer */
	if add {
		/* Enqueue */
		QUEUE.PushBack(newQaddr(a))
		/* Wake up a goroutine if one's waiting */
		QCOND.Signal()
		debug("%v Queued")
	}
}

/* scanner pops an IP off the queue and scans it */
func scanner(nAttempt uint) {
	debug("Scanner started")
	for {
		/* Wait for something to be enqueued */
		QLOCK.Lock()
		for 0 == QUEUE.Len() {
			debug("Scanner sleeping")
			QCOND.Wait()
			debug("Scanner woke up")
		}

		/* Pop off the first address */
		a := QUEUE.Front().Value.(qaddr)
		start := time.Now()
		SCANNING[a.a] = start
		QUEUE.Remove(QUEUE.Front())
		QLOCK.Unlock()

		/* Scan it */
		res := scan(a.a, nAttempt, start)

		/* Update database and state */
		QLOCK.Lock()
		delete(SCANNING, a.a)
		if err := DB.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(RESBUCKET))
			return bucket.Put([]byte(a.a), res)
		}); err != nil {
			log.Printf("Error saving result for %v: %v", a, err)
		}
		QLOCK.Unlock()
	}
}

/* updateAverages updates the average time a scan takes */
func updateAverages(sd time.Duration) {
	AVGLOCK.Lock()
	defer AVGLOCK.Unlock()
	AVGTIME = ((AVGTIME * time.Duration(NSCAN)) + sd) /
		time.Duration(NSCAN+1)
	NSCAN++
}

/* TODO: Redirect back to non-?yes */
