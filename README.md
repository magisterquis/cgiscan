cgiscan
=======
CGI Service to portscan and bannergrab the requestor

When asked (by default via `/cgiscan/scan`) it will queue and eventually
synscan the requestor's TCP ports, and grab banner for any ports to which it
can make a connection.  Please see `/cgiscan/help` for more queryable URLs.

This is intended for easy, lightweight self-service scanning for users setting
up servers, VMs, etc..  After a scan has been requested, it's status can be
queried by accessing the same URL.  Scans take aroud 15 minutes.  This can be
sped up with the `-n` parameter at the cost of increased resource usage.

It can also run as a [standalone](#standalone-operation) HTTPS server, given a
TLS certificate and key.

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

Standalone Operation
--------------------
Besides running as a FastCGI service, cgiscan can run as a standalone HTTPS
server.  To do this, it requires a TLS certificate and key.  It should probably
be started something like
```sh
./cgiscan -d -s 0.0.0.0:7733 -p / -https -cert /your/cert.pem -key /your/key.pem -db /your/db.pem
```
Of note is `-p /`, which prevents users from having to prepend `/cgiscan` to
all URL paths.  It is not necessary to specify `-d`, but it displays a
reasonable amount of logging data.  Log rotation is probably a good idea,
however.

Scanning Arbitrary IP Addresses
-------------------------------
Scans for arbitrary IP addresses can be queued via an option Unix domain
socket, specified with the `-q` flag.
```bash
# Fire off cgiscan
./cgiscan -https -t -s localhost:7733 -db ./db -d -p / -q ./q.sock

# Queue up an address
nc -U 192.168.0.1 | nc -U ./q.sock
```
This allows for somewhat easy collaboration during security assessments, as a
less noisy alternative to [fastscan](https://github.com/magisterquis/fastscan).

In the future it may be possible to queue arbitrary addresses via a GET request
as well.

Binaries
--------
Binaries, even for Windows, can be made available upon request.  I can usually
be found on Freenode with the nick `magisterquis`.

Windows
-------
Should probably work.  It could even be made into a standalone webserver
without too much fuss.
