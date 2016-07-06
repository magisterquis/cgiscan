package main

/*
 * status.go
 * Main (status) page
 * By J. Stuart McMurray
 * Created 20160706
 * Last Modified 20160706
 */

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

/* Status reports a requestor's status */
func status(w http.ResponseWriter, req *http.Request) {
	/* Get the requestor's address */
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}

	/* Work out queue position and if it's scanning, and associated time */
	queued, started, startTime, qpos, qlen := inQueue(ip)

	/* Come up with a helpful status message */
	var qmsg string
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
	} else if queued { /* Report queue position */
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
		qmsg = fmt.Sprintf(
			"<A HREF=\"%v/scan\">Click here to (re)scan</A>",
			URLPATH,
		)
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
			`<!DOCTYPE HTML>
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
`,
			ip,
			qmsg,
			qlen,
			time.Now().Sub(START),
			NSCAN,
			AVGTIME,
			res,
		),
	)
	debug("%v Reported status: %v", qmsg)
}

/* inQueue checks a's position in the queue, and returns whetehr it's being
scanned, how long it's been waiting/been scanned, it's queue position, and the
queue length */
func inQueue(
	a string,
) (queued, started bool, startTime time.Time, qpos, qlen int) {
	/* TODO: Make this function do one thing and do it well */
	/* This whole thing should probably be replaced by a circular buffer */
	QLOCK.Lock()
	defer QLOCK.Unlock()
	/* If we're already started, easy day */
	if st, ok := SCANNING[a]; ok {
		return false, true, st, 0, QUEUE.Len()
	}
	/* Make sure we're not in the queue already */
	pos := 1
	for e := QUEUE.Front(); nil != e; e = e.Next() {
		q := e.Value.(qaddr)
		/* If we are, report the position */
		if q.a == a {
			return true, false, q.t, pos, QUEUE.Len()
		}
		pos++
	}
	/* Not in the queue, not running, maybe add it */
	return false, false, time.Time{}, 0, QUEUE.Len()
}
