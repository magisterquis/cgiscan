package main

/*
 * query.go
 * Query for an IP's last scan
 * By J. Stuart McMurray
 * Created 20160705
 * Last Modified 20160706
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
	parts := strings.Split(req.URL.path, "/")
	addr := parts[len(parts)-1]
	/* Usage */
	if nil == net.ParseIP(a) {
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
	/* No result */
	if nil == res {
		io.WriteString(w, fmt.Sprintf("No scan results for %v", addr))
	}
	w.Write(res)
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
