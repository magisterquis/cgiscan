package main

/*
 * query.go
 * Query for an IP's last scan
 * By J. Stuart McMurray
 * Created 20160705
 * Last Modified 20160708
 */

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/boltdb/bolt"
)

/* Query returns the last scan results for a given IP */
func query(w http.ResponseWriter, req *http.Request) {
	/* Pull out query address, if any */
	parts := strings.Split(req.URL.Path, "/")
	addr := parts[len(parts)-1]
	/* Usage */
	if nil == net.ParseIP(addr) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(
			"No IP address specified.  The last element of the " +
				"URL must be an IP address.",
		))
	}
	/* Last scan result */
	res, err := lastRes(addr)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}

	/* Requestor's IP */
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}

	/* No result */
	if nil == res {
		io.WriteString(w, fmt.Sprintf("No scan results for %v", addr))
		debug("%v sent no report for %v", ip, addr)
		return
	}

	/* Send result */
	if _, err := w.Write([]byte(fmt.Sprintf(`<!DOCTYPE HTML>
<HEAD>
	<TITLE>CGIS:%v</TITLE>
	<STYLE TYPE="text/css"><!--
		body {
			background-color: white;
			color: black;
			font-family: 'Comic Sans MS', 'Chalkboard SE', 'Comic Neue', sans-serif;
		}
	--></STYLE>
</HEAD>
<BODY>
<H1>Scan Result for %v</H1>
<PRE>
`, addr, addr))); nil != err {
		return
	}
	if _, err := w.Write(res); nil != err {
		return
	}
	io.WriteString(w, "\n</PRE>\n</BODY>\n<HTML>\n")
	debug("%v sent report for %v", ip, addr)
}

/* lastRes gets the last results for the scanned IP */
func lastRes(ip string) ([]byte, error) {
	var res []byte /* Scan results */
	err := DB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(RESBUCKET))
		value := bucket.Get([]byte(ip))
		/* Return nil if there's no previous scan */
		if nil == value {
			return nil
		}
		/* Copy the data to a returnable slice */
		res = make([]byte, len(value))
		copy(res, value)
		return nil
	})
	return res, err
}
