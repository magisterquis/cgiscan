package main

/*
 * delete.go
 * Delete a saved scan
 * By J. Stuart McMurray
 * Created 20160706
 * Last Modified 20160706
 */

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/boltdb/bolt"
)

/* deleteResult removes scan results from the database */
func deleteResult(w http.ResponseWriter, req *http.Request) {
	/* Get the requestor's address */
	rip, _, err := net.SplitHostPort(req.RemoteAddr)
	if nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}
	/* Remove entry from the database */
	err := DB.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(RESBUCKET))
		r := []byte(rip)
		/* If we don't have saved results, give up */
		if nil == bucket.Get(r) {
			return fmt.Errorf(
				"No scan result to delete for %v",
				rip,
			)
		}
		return bucket.Delete([]byte(rip))
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		debug("%v Failed to delete saved results: %v", rip, err)
		return
	}
	io.WriteString(w, "Deleted saved results.")
	debug("%v Deleted saved results")

}
