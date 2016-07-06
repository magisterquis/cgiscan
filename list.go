package main

/*
 * list.go
 * List scanned hosts
 * By J. Stuart McMurray
 * Created 20160706
 * Last Modified 20160706
 */

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"

	"github.com/boltdb/bolt"
)

/* List returns the list of scanned hosts */
func listScanned(w http.ResponseWriter, req *http.Request) {
	/* Get the requestor's address */
	rip, _, err := net.SplitHostPort(req.RemoteAddr)
	if nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}

	/* List of IP Addresses */
	ips := make([]string, 0)

	/* Get the list of addresses */
	if err := DB.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(RESBUCKET))
		/* Iterate over all the keys */
		c := bucket.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			/* []byte -> String -> []byte -> string */
			ip := net.ParseIP(string(k))
			if ip4 := ip.To4(); nil != ip4 {
				ip = ip4
			}
			ips = append(ips, string(ip))
		}
		return nil
	}); nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}

	/* Sort list of IPs */
	sort.Strings(ips)

	/* Return them */
	if _, err := io.WriteString(
		w,
		`<!DOCTYPE HTML>
<HEAD>
	<TITLE>CGIScanned</TITLE>
	<STYLE TYPE="text/css"><!--
		body {
			background-color: white;
			color: black;
			font-family: 'Comic Sans MS', 'Chalkboard SE', 'Comic Neue', sans-serif;
		}
	--></STYLE>
</HEAD>
<BODY>
<H1>Scanned IP Addresses</H1>
<P>
`); nil != err {
		return
	}
	for _, ip := range ips {
		a := net.IP(ip).String()
		if _, err := w.Write([]byte(fmt.Sprintf(
			"<A HREF=\"%v/res/%v\">%v</A><BR>\n",
			URLPATH,
			a,
			a,
		))); nil != err {
			return
		}
	}
	io.WriteString(w, "</P>\n</BODY>\n</HTML>\n")

	debug("%v Sent list of %v address links", rip, len(ips))
}

/* TODO: Templates? :( */
