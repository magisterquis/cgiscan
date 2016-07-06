package main

/*
 * help.go
 * Help message for cgiscan
 * By J. Stuart McMurray
 * Created 20160706
 * Last Modified 20160706
 */

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

/* help sends back a nice help message */
func help(w http.ResponseWriter, req *http.Request) {
	/* Get the requestor's address */
	rip, _, err := net.SplitHostPort(req.RemoteAddr)
	if nil != err {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, err.Error())
		return
	}
	debug("%v help", rip)
	io.WriteString(w, fmt.Sprintf(`<!DOCTYPE HTML>
<HEAD>
	<TITLE>CGIScan Help</TITLE>
	<STYLE TYPE="text/css"><!--
		body {
			background-color: white;
			color: black;
			font-family: 'Comic Sans MS', 'Chalkboard SE', 'Comic Neue', sans-serif;
		}
	--></STYLE>
</HEAD>
<BODY>
<H1>Halp!</H1>
	<H2>Introduction</H2>
		<P>Syn-scans the requestor's IP address.  After 
			<A HREF="%v/scan">%v/scan</A> has been requested, the
			requestor's IP address will be queued for scanning.</P>
		<P>Please see the list of URLs below for more details.</P>
	<H2>URLs</H2>
		<P>"API" endpoints, which should work nicely in a browser.</P>
		<H3><A HREF="%v/delete/">%v/delete</A></H3>
			<P>Remove an IP address' scan results</P>
		<H3><A HREF="%v/help">%v/help</A></H3>
			<P>This help<P>
		<H3><A HREF="%v/list">%v/list</A></H3>
			<P>List the scanned IP addresses</P>
		<H3><A HREF="%v/queue">%v/queue</A></H3>
			<P>Lists the scan queue</P>
		<H3><A HREF="%v/res/&lt;address&gt;">%v/res/&lt;address&gt;</A></H3>
			<P>Returns the results of the last scan to the
			given address</P>
		<H3><A HREF="%v/scan">%v/scan</A></H3>
			<P>Queues up a scan</P>
		<H3><A HREF="%v/status">%v/status</A></H3>
			<P>Server status</P>
	<H2>Contact</H2>
		<P>Please contact the owner of this website with any
			questions or to report abuse.</P>
		<P>The source to this scanner is at
			<A HREF="https://github.com/magisterquis/cgiscan">
			https://github.com/magisterquis/cgiscan</A>.  The
			author can usually be found on
			<A HREF="http://webchat.freenode.net?channels=%%23cgiscan&uio=d4">
			Freenode</A> with the nick MagisterQuis.</P>
</BODY>
</HTML>
`,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
		URLPATH,
	))
}
