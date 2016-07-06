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

const (
	/* Scan Response template */
	SCANRES = `<!DOCTYPE HTML>
<HTML>
<HEAD>
	<TITLE>CGIScan</TITLE>
	<STYLE TYPE="text/css"><!--
		body {
			background-color: white;
			color: black;
			font-family: 'Comic Sans MS', 'Chalkboard SE', 'Comic Neue', sans-serif;
		}
		p {
			font-size: xx-small;
		}
	--></STYLE>
</HEAD>
<BODY>
	<H1>CGIScan for %v</H1>
	<P>More information at
		<A HREF="https://github.com/magisterquis/cgiscan">
			https://github.com/magisterquis/cgiscan
		</A>
	</P>
	<PRE>
%v

     Queue length: %v
   Service uptime: %v
  Completed scans: %v
Average scan time: %v

Most recent scan results:

%s
</PRE>
</BODY>
</HTML>
`
	RESBUCKET = "Results" /* Bucket name for results */
)

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
		"Scan finished at %v",
		time.Now().UTC().Format(time.RFC3339),
	)

	/* No ports is an easy case */
	if 0 == len(m) {
		fmt.Fprintf(report, "\n\nNo ports open.")
		return report.Bytes()
	}

	/* Sorted open ports list */
	os := make([]int, 0, len(m))
	for k := range m {
		os = append(os, k)
	}
	sort.Ints(os)

	/* Header */
	fmt.Fprintf(report, "\n\n  Port | Banner")
	fmt.Fprintf(report, "\n-------+-------")

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
		fmt.Fprintf(report, "\n%-6v | %v", o, banner)
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

	/* Work out if we should scan it */
	scan, err := shouldScan(req)
	if nil != err {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, err.Error())
		return
	}

	/* If we're meant to scan, queue it up */
	var qmsg string
	started, startTime, qpos, qlen := enqueue(ip, scan)
	wt := time.Now().Sub(startTime) /* Time since startTime */
	/* Come up with a helpful message */
	if started { /* Report that we're scanning */
		st := startTime.UTC().Format(time.RFC3339) /* Start Time */
		qmsg = fmt.Sprintf(
			"Scanning now.  Start time %v (%v ago).",
			st,
			wt,
		)
		debug("%v Reporting running since %v (%v)", ip, st, wt)
	} else if scan { /* Report queue position */
		qmsg = fmt.Sprintf(
			"Queue position: %v (waiting %v)",
			qpos,
			wt,
		)
		debug(
			"%v Reporting queued in position %v (%v)",
			ip,
			qpos,
			wt,
		)
	} else { /* Report last results */
		debug("%v Reporting results", ip)
	}

	/* Get the last results */
	res, err := lastRes(ip)
	if nil != err {
		res = []byte(fmt.Sprintf("ERROR: %v", err))
	}
	if nil == res || 0 == len(res) {
		res = []byte("\nNo results.")
	}

	/* Return them */
	io.WriteString(
		w,
		fmt.Sprintf(
			SCANRES,
			ip,
			qmsg,
			qlen,
			time.Now().Sub(START), NSCAN, AVGTIME,
			res,
		),
	)
}

/* shouldScan returns true if a scan was requested */
func shouldScan(req *http.Request) (bool, error) {
	/* Parse form values */
	if err := req.ParseForm(); nil != err {
		return false, err
	}

	/* Work out whether a scan is requested */
	if _, ok := req.Form["yes"]; ok {
		return true, nil
	}
	return false, nil
}

/* enqueue optionally puts the address in the queue for scanning, and returns
the position in the queue as well as the length of the queue. */
func enqueue(
	a string,
	add bool,
) (started bool, startTime time.Time, pos, len int) {
	/* TODO: Make this function do one thing and do it well */
	/* This whole thing should probably be replaced by a circular buffer */
	QLOCK.Lock()
	defer QLOCK.Unlock()
	/* If we're already started, easy day */
	if st, ok := SCANNING[a]; ok {
		return true, st, 0, QUEUE.Len()
	}
	/* Make sure we're not in the queue already */
	pos = 1
	for e := QUEUE.Front(); nil != e; e = e.Next() {
		q := e.Value.(qaddr)
		/* If we are, report the position */
		if q.a == a {
			return false, q.t, pos, QUEUE.Len()
		}
		pos++
	}
	/* Not in the queue, not running, maybe add it */
	if add {
		q := newQaddr(a)
		/* Enqueue */
		QUEUE.PushBack(q)
		/* Wake up a goroutine if one's waiting */
		QCOND.Signal()
		return false, q.t, QUEUE.Len(), QUEUE.Len()
	} else {
		/* Not running, not queued, don't add it */
		return false, time.Time{}, 0, QUEUE.Len()
	}
	/* TODO: Check again if we're being scanned */
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
