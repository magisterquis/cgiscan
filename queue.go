package main

/*
 * queue.go
 * Return the queue
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

/* sendQueue returns the queue to the requestor */
func sendQueue(w http.ResponseWriter, req *http.Request) {
	QLOCK.Lock()
	defer QLOCK.Unlock()

	/* Get the requestor's address */
	rip, _, err := net.SplitHostPort(req.RemoteAddr)
	if nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}

	/* Get IPs being scanned */
	ss := make([]qaddr, 0, len(SCANNING))
	for k, v := range SCANNING {
		ss = append(ss, qaddr{a: k, t: v})
	}

	/* Copy the IPs in the queue, to keep the locking short */
	qs := make([]qaddr, 0, QUEUE.Len())
	for e := QUEUE.Front(); nil != e; e = e.Next() {
		qs = append(qs, e.Value.(qaddr))
	}

	/* Send queue to the user */
	if _, err := io.WriteString(w, `<!DOCTYPE HTML>
<HEAD>
	<TITLE>CGIScan Queue</TITLE>
	<STYLE TYPE="text/css"><!--
		body {
			background-color: white;
			color: black;
			font-family: 'Comic Sans MS', 'Chalkboard SE', 'Comic Neue', sans-serif;
		}
	--></STYLE>
</HEAD>
<BODY>
`); nil != err {
		return
	}

	/* Send hosts being scanned */
	if _, err := io.WriteString(w, "<H1>Currently Being Scanned</H1>\n<P>\n"); nil != err {
		return
	}
	/* Note if it's empty */
	if 0 == len(ss) {
		if _, err := io.WriteString(w, "None.\n"); nil != err {
			return
		}
	}
	for _, s := range ss {
		if err := writeQaddr(w, s); nil != err {
			return
		}
	}

	/* Send Queue */
	if _, err := io.WriteString(w, "</P>\n<H1>Scan Queue</H1>\n<P>\n"); nil != err {
		return
	}
	/* Note if it's empty */
	if 0 == len(qs) {
		if _, err := io.WriteString(w, "None.\n"); nil != err {
			return
		}
	}
	for _, q := range qs {
		if err := writeQaddr(w, q); nil != err {
			return
		}
	}

	/* Close document */
	if _, err := io.WriteString(w, "</P>\n</BODY>\n</HEAD>\n"); nil != err {
		return
	}

	debug("%v sent queue", rip)

}

/* writeQaddr writes the queued qaddr q to w */
func writeQaddr(w io.Writer, q qaddr) error {
	if _, err := w.Write([]byte(fmt.Sprintf(
		"%v <A HREF=\"%v/res/%v\">%v</A><BR>\n",
		q.t.Format(time.RFC3339),
		URLPATH,
		q.a,
		q.a,
	))); nil != err {
		return err
	}
	return nil
}
