cgiscan
=======
CGI Service to portscan and bannergrab the requestor

When the CGI script is run (by default by making a request to `/cgiscan`), it
fires off a scan of the requestor's TCP ports (or queues it if a scan's
already running).  The scan is only started if a `yes` parameter is supplied
in the request (i.e. `/cgiscan?yes`).

This is intended for easy, lightweight self-service scanning for users setting
up servers, VMs, etc..  After a scan has been requested, it's status can be
queried by accessing the same URL.  Scans take aroud 15 minutes.  This can be
sped up with the `-n` parameter at the cost of increased resource usage.

Setup
-----
The below directions are for OpenBSD's `httpd(8)`.  Please adjust for your
own webserver.

### Installation
Download the source, compile the binary
```bash
go get github.com/magisterquis/cgiscan
go install github.com/magisterquis/cgiscan
doas cp `which cgiscan` /var/www/bin/cgiscan
doas chown root:bin /var/www/bin/cgiscan
doas chmod 0755 /var/www/bin/cgiscan
```
Add a directory in httpd's chroot for `cgiscan`
```bash
doas mkdir /var/www/run/cgiscan
doas chown www:www /var/www/run/cgiscan
doas chmod 0755 /var/www/run/cgiscan
```

### Configure `httpd(8)`
Tell `httpd(8)` expect a CGI socket in `httpd.conf`
```
/etc/httpd.conf:

server "www.foo.com" {
        # Serve up the scanner
        location "/cgiscan" {
                fastcgi socket "/run/cgiscan/cgiscan.sock"
        }
}
```

### Fire off cgiscan
```bash
doas /usr/bin/nohup /usr/sbin/chroot -u www -g www /var/www /bin/cgiscan &
```
The above (less `doas`) can be put into /etc/rc.local to be launched on boot.
```bash
/etc/rc.local:

/usr/bin/nohup /usr/sbin/chroot -u www -g www /var/www /bin/cgiscan &
```

Configuration
-------------
All configuration is performed via the command line.  Pass the `-h` flag to see
the available options.

Binaries
--------
Binaries, even for Windows, can be made available upon request.  I can usually
be found on Freenode with the nick `magisterquis`.

Windows
-------
Should probably work.  It could even be made into a standalone webserver
without too much fuss.
