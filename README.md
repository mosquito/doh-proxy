# DNS Over HTTPS proxy server 

This image allows you to run a caching DNS server on your local network, and requests will be 
proxied to DoH (DNS over HTTPS) servers of service providers or your own.

Technically there are several proxy server processes running and `dnsmasq` making requests to them.

## Simple example

```shell
docker run mosquito/doh-proxy
```

selected providers by default is:

* `cloudflare-dns.com`
* `dns.google`
* `doh.opendns.com`

## Example with explicitly use selected service providers

```shell
docker run \
  -e DOH_PROVIDERS=cloudflare-dns.com,dns.adguard.com,doh.pub \
  mosquito/doh-proxy
```

## Example with custom DoH url

```shell
docker run \
  -e DOH_URLS=https://dns.google/dns-query,https://doh.libredns.gr/dns-query \
  mosquito/doh-proxy
```

## Available providers

| Provider Alias                              | Provider name                                 |
|---------------------------------------------|-----------------------------------------------|
| `cloudflare-dns.com`                        | Cloudflare                                    |
| `ControlD-Malware-Ads-Social`               | ControlD (Block Malware + Ads + Social)       |
| `ControlD-Malware-Ads`                      | ControlD (Block Malware + Ads)                |
| `ControlD-Malware`                          | ControlD (Block Malware)                      |
| `ControlD-Unfiltered`                       | ControlD (Unfiltered)                         |
| `basic.rethinkdns.com`                      | Rethink DNS (Configurable)                    |
| `blitz.ahadns.com`                          | AhaDNS Blitz (Configurable)                   |
| `dns-family.adguard.com`                    | AdGuard (Family Protection)                   |
| `dns-family.adguard.com`                    | AdGuard (Family Protection)                   |
| `dns-unfiltered.adguard.com`                | AdGuard (Non-filtering)                       |
| `dns.adguard.com`                           | AdGuard (Standard)                            |
| `dns.cfiec.net`                             | CFIEC Public DNS (IPv6 Only)                  |
| `dns.comss.one`                             | Comss.ru DNS (West)                           |
| `dns.decloudus.com`                         | DeCloudUs DNS                                 |
| `dns.digitale-gesellschaft.ch`              | Digitale Gesellschaft - CH                    |
| `dns.east.comss.one`                        | Comss.ru DNS (East)                           |
| `dns.google`                                | Google                                        |
| `dns.nextdns.io`                            | NextDNS.io (Configurable)                     |
| `dns.oszx.co`                               | OSZX DNS - UK                                 |
| `dns.pumplex.com`                           | OSZX DNS (Pumplex)                            |
| `dns.quad9.net`                             | Quad 9 (Recommended)                          |
| `dns.rubyfish.cn`                           | rubyfish.cn                                   |
| `dns.switch.ch`                             | Switch DNS - CH                               |
| `dns.tuna.tsinghua.edu.cn`                  | Tsinghua University Secure DNS - CN           |
| `dns.twnic.tw`                              | Quad 101 - TW                                 |
| `dns10.quad9.net`                           | Quad 9 (Unsecured)                            |
| `dns11.quad9.net`                           | Quad 9 (Secured with ECS Support)             |
| `dns9.quad9.net`                            | Quad 9 (Secured)                              |
| `dnsforfamily`                              | DNS For Family                                |
| `dnsforge.de`                               | DNS Forge - DE                                |
| `doh-2.seby.io`                             | Seby DNS - AU                                 |
| `doh-ch.blahdns.com`                        | BlahDNS - CH                                  |
| `doh-de.blahdns.com`                        | BlahDNS - DE                                  |
| `doh-fi.blahdns.com`                        | BlahDNS - FI                                  |
| `doh-jp.blahdns.com`                        | BlahDNS - JP                                  |
| `doh-sg.blahdns.com`                        | BlahDNS - SG                                  |
| `doh.360.cn`                                | 360 Secure DNS - CN                           |
| `doh.applied-privacy.net`                   | Applied Privacy DNS - AT/DE                   |
| `doh.au.ahadns.net`                         | AhaDNS - AU (Block Malware + Ads)             |
| `doh.chi.ahadns.net`                        | AhaDNS - US/Chicago (Block Malware + Ads)     |
| `doh.cleanbrowsing.org-doh-adult-filter`    | CleanBrowsing (Adult Filter)                  |
| `doh.cleanbrowsing.org-doh-family-filter`   | CleanBrowsing (Family Filter)                 |
| `doh.cleanbrowsing.org-doh-security-filter` | CleanBrowsing (Security Filter)               |
| `doh.dns.sb`                                | DNS.SB                                        |
| `doh.dnslify.com`                           | DNSlify DNS                                   |
| `doh.es.ahadns.net`                         | AhaDNS - ES (Block Malware + Ads)             |
| `doh.familyshield.opendns.com`              | OpenDNS (Family Shield)                       |
| `doh.ffmuc.net`                             | FFMUC DNS - DE                                |
| `doh.idnet.net`                             | IDNet.net - UK                                |
| `doh.in.ahadns.net`                         | AhaDNS - IN (Block Malware + Ads)             |
| `doh.it.ahadns.net`                         | AhaDNS - IT (Block Malware + Ads)             |
| `doh.la.ahadns.net`                         | AhaDNS - US/Los Angeles (Block Malware + Ads) |
| `doh.libredns.gr-ads`                       | LibreDNS - GR (No Ads)                        |
| `doh.libredns.gr`                           | LibreDNS - GR                                 |
| `doh.nl.ahadns.net`                         | AhaDNS - NL (Block Malware + Ads)             |
| `doh.no.ahadns.net`                         | AhaDNS - NO (Block Malware + Ads)             |
| `doh.ny.ahadns.net`                         | AhaDNS - US/New York (Block Malware + Ads)    |
| `doh.opendns.com`                           | OpenDNS                                       |
| `doh.pl.ahadns.net`                         | AhaDNS - PL (Block Malware + Ads)             |
| `doh.pub`                                   | DNSPod Public DNS - CN                        |
| `doh.tiar.app`                              | Tiarap Public DNS - SG                        |
| `doh.tiar.jp`                               | Tiarap Public DNS - JP                        |
| `family.canadianshield.cira.ca`             | CIRA Canadian Shield (Family)                 |
| `family.cloudflare-dns.com`                 | Cloudflare (Family Protection)                |
| `fi.doh.dns.snopyta.org`                    | Snopyta DNS - FI                              |
| `freedns.controld.com-family`               | ControlD (Family)                             |
| `freedns.controld.com-p0`                   | ControlD (Unfiltered)                         |
| `freedns.controld.com-p1`                   | ControlD (Block Malware)                      |
| `freedns.controld.com-p2`                   | ControlD (Block Malware + Ads)                |
| `freedns.controld.com-p3`                   | ControlD (Block Malware + Ads + Social)       |
| `kaitain.restena.lu`                        | Restena DNS - LU                              |
| `odvr.nic.cz`                               | ODVR (nic.cz)                                 |
| `ordns.he.net`                              | Hurricane Electric                            |
| `private.canadianshield.cira.ca`            | CIRA Canadian Shield (Private)                |
| `protected.canadianshield.cira.ca`          | CIRA Canadian Shield (Protected)              |
| `public.dns.iij.jp`                         | IIJ Public DNS - JP                           |
| `resolver-eu.lelux.fi`                      | Lelux DNS - FI                                |
| `security.cloudflare-dns.com`               | Cloudflare (Security Protection)              |


## Customize `dnsmasq` behaviour

Any dnsmasq option can be passed in an environment variable that matches the following pattern:

* `DNSMASQ_{OPTION_NAME}={OPTION_VALUE}`

If you need to pass multiple options this should look like a valid python list.

* `DNSMASQ_LISTEN_ADDRESS="['::', '0.0.0.0']"` means `--listen-address=:: --listen-address=0.0.0.0`

To override an option, such as a declared default, you must pass it the value `False`:

* `DNSMASQ_NO_RESOLV=True` means `--no-resolv`
* `DNSMASQ_NO_RESOLV=False` ignored

### Defaults

* `DOH_PROVIDERS=cloudflare-dns.com,dns.google,doh.opendns.com`
* `DNSMASQ_CACHE_SIZE=500000`
* `DNSMASQ_LISTEN_ADDRESS="['::', '0.0.0.0']"`
* `DNSMASQ_NO_HOSTS=True`
* `DNSMASQ_NO_NEGCACHE=True`
* `DNSMASQ_NO_POLL=True`
* `DNSMASQ_NO_RESOLV=True`
* `DNSMASQ_PORT=53`
* `DNSMASQ_STRICT_ORDER=True`
* `DNSMASQ_USE_STALE_CACHE=48h`
