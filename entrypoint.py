#!/usr/bin/env python3
import logging
import os
import pwd
from ast import literal_eval
from dataclasses import dataclass
from multiprocessing import Process
from pathlib import Path
from shutil import which
from typing import Mapping, Optional, Tuple, List, Dict


@dataclass
class Provider:
    alias: str
    name: str
    url: str


PROVIDERS = {
    provider.alias: provider for provider in (
        Provider(
            alias="doh.tiar.app",
            name="Tiarap Public DNS - SG",
            url="https://doh.tiar.app/dns-query",
        ),
        Provider(
            alias="doh.tiar.jp",
            name="Tiarap Public DNS - JP",
            url="https://doh.tiar.jp/dns-query",
        ),
        Provider(
            alias="family.canadianshield.cira.ca",
            name="CIRA Canadian Shield (Family)",
            url="https://family.canadianshield.cira.ca/dns-query",
        ),
        Provider(
            alias="private.canadianshield.cira.ca",
            name="CIRA Canadian Shield (Private)",
            url="https://private.canadianshield.cira.ca/dns-query",
        ),
        Provider(
            alias="protected.canadianshield.cira.ca",
            name="CIRA Canadian Shield (Protected)",
            url="https://protected.canadianshield.cira.ca/dns-query",
        ),
        Provider(
            alias="dns.digitale-gesellschaft.ch",
            name="Digitale Gesellschaft - CH",
            url="https://dns.digitale-gesellschaft.ch/dns-query",
        ),
        Provider(
            alias="dns.switch.ch",
            name="Switch DNS - CH",
            url="https://dns.switch.ch/dns-query",
        ),
        Provider(
            alias="doh.360.cn",
            name="360 Secure DNS - CN",
            url="https://doh.360.cn/dns-query",
        ),
        Provider(
            alias="dns.tuna.tsinghua.edu.cn",
            name="Tsinghua University Secure DNS - CN",
            url="https://dns.tuna.tsinghua.edu.cn:8443/dns-query",
        ),
        Provider(
            alias="dns.rubyfish.cn",
            name="rubyfish.cn",
            url="https://dns.rubyfish.cn/dns-query",
        ),
        Provider(
            alias="dns.oszx.co",
            name="OSZX DNS - UK",
            url="https://dns.oszx.co/dns-query",
        ),
        Provider(
            alias="dns-family.adguard.com",
            name="AdGuard (Family Protection)",
            url="https://dns-family.adguard.com/dns-query",
        ),
        Provider(
            alias="dns.adguard.com",
            name="AdGuard (Standard)",
            url="https://dns.adguard.com/dns-query",
        ),
        Provider(
            alias="blitz.ahadns.com",
            name="AhaDNS Blitz (Configurable)",
            url="https://blitz.ahadns.com/",
        ),
        Provider(
            alias="doh-ch.blahdns.com",
            name="BlahDNS - CH",
            url="https://doh-ch.blahdns.com/dns-query",
        ),
        Provider(
            alias="doh-de.blahdns.com",
            name="BlahDNS - DE",
            url="https://doh-de.blahdns.com/dns-query",
        ),
        Provider(
            alias="doh-fi.blahdns.com",
            name="BlahDNS - FI",
            url="https://doh-fi.blahdns.com/dns-query",
        ),
        Provider(
            alias="doh-jp.blahdns.com",
            name="BlahDNS - JP",
            url="https://doh-jp.blahdns.com/dns-query",
        ),
        Provider(
            alias="doh-sg.blahdns.com",
            name="BlahDNS - SG",
            url="https://doh-sg.blahdns.com/dns-query",
        ),
        Provider(
            alias="family.cloudflare-dns.com",
            name="Cloudflare (Family Protection)",
            url="https://family.cloudflare-dns.com/dns-query",
        ),
        Provider(
            alias="cloudflare-dns.com",
            name="Cloudflare",
            url="https://cloudflare-dns.com/dns-query",
        ),
        Provider(
            alias="security.cloudflare-dns.com",
            name="Cloudflare (Security Protection)",
            url="https://security.cloudflare-dns.com/dns-query",
        ),
        Provider(
            alias="freedns.controld.com-family",
            name="ControlD (Family)",
            url="https://freedns.controld.com/family",
        ),
        Provider(
            alias="ControlD-Malware-Ads-Social",
            name="ControlD (Block Malware + Ads + Social)",
            url="https://freedns.controld.com/p3",
        ),
        Provider(
            alias="ControlD-Malware-Ads",
            name="ControlD (Block Malware + Ads)",
            url="https://freedns.controld.com/p2",
        ),
        Provider(
            alias="ControlD-Malware",
            name="ControlD (Block Malware)",
            url="https://freedns.controld.com/p1",
        ),
        Provider(
            alias="freedns.controld.com-p0",
            name="ControlD (Unfiltered)",
            url="https://freedns.controld.com/p0",
        ),
        Provider(
            alias="freedns.controld.com-p1",
            name="ControlD (Block Malware)",
            url="https://freedns.controld.com/p1",
        ),
        Provider(
            alias="freedns.controld.com-p2",
            name="ControlD (Block Malware + Ads)",
            url="https://freedns.controld.com/p2",
        ),
        Provider(
            alias="freedns.controld.com-p3",
            name="ControlD (Block Malware + Ads + Social)",
            url="https://freedns.controld.com/p3",
        ),
        Provider(
            alias="ControlD-Unfiltered",
            name="ControlD (Unfiltered)",
            url="https://freedns.controld.com/p0",
        ),
        Provider(
            alias="dns.decloudus.com",
            name="DeCloudUs DNS",
            url="https://dns.decloudus.com/dns-query",
        ),
        Provider(
            alias="dnsforfamily",
            name="DNS For Family",
            url="https://dns-doh.dnsforfamily.com/dns-query",
        ),
        Provider(
            alias="doh.dnslify.com",
            name="DNSlify DNS",
            url="https://doh.dnslify.com/dns-query",
        ),
        Provider(
            alias="doh.opendns.com",
            name="OpenDNS",
            url="https://doh.opendns.com/dns-query",
        ),
        Provider(
            alias="doh.familyshield.opendns.com",
            name="OpenDNS (Family Shield)",
            url="https://doh.familyshield.opendns.com/dns-query",
        ),
        Provider(
            alias="dns.pumplex.com",
            name="OSZX DNS (Pumplex)",
            url="https://dns.pumplex.com/dns-query",
        ),
        Provider(
            alias="basic.rethinkdns.com",
            name="Rethink DNS (Configurable)",
            url="https://basic.rethinkdns.com/",
        ),
        Provider(
            alias="odvr.nic.cz",
            name="ODVR (nic.cz)",
            url="https://odvr.nic.cz/doh",
        ),
        Provider(
            alias="dnsforge.de",
            name="DNS Forge - DE",
            url="https://dnsforge.de/dns-query",
        ),
        Provider(
            alias="resolver-eu.lelux.fi",
            name="Lelux DNS - FI",
            url="https://resolver-eu.lelux.fi/dns-query",
        ),
        Provider(
            alias="dns.google",
            name="Google",
            url="https://dns.google/dns-query",
        ),
        Provider(
            alias="doh.libredns.gr-ads",
            name="LibreDNS - GR (No Ads)",
            url="https://doh.libredns.gr/ads",
        ),
        Provider(
            alias="doh.libredns.gr",
            name="LibreDNS - GR",
            url="https://doh.libredns.gr/dns-query",
        ),
        Provider(
            alias="dns-family.adguard.com",
            name="AdGuard (Family Protection)",
            url="https://dns-family.adguard.com/dns-query",
        ),
        Provider(
            alias="dns-unfiltered.adguard.com",
            name="AdGuard (Non-filtering)",
            url="https://dns-unfiltered.adguard.com/dns-query",
        ),
        Provider(
            alias="dns.adguard.com",
            name="AdGuard (Standard)",
            url="https://dns.adguard.com/dns-query",
        ),
        Provider(
            alias="dns.nextdns.io",
            name="NextDNS.io (Configurable)",
            url="https://dns.nextdns.io/",
        ),
        Provider(
            alias="doh-2.seby.io",
            name="Seby DNS - AU",
            url="https://doh-2.seby.io/dns-query",
        ),
        Provider(
            alias="public.dns.iij.jp",
            name="IIJ Public DNS - JP",
            url="https://public.dns.iij.jp/dns-query",
        ),
        Provider(
            alias="kaitain.restena.lu",
            name="Restena DNS - LU",
            url="https://kaitain.restena.lu/dns-query",
        ),
        Provider(
            alias="doh.au.ahadns.net",
            name="AhaDNS - AU (Block Malware + Ads)",
            url="https://doh.au.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.chi.ahadns.net",
            name="AhaDNS - US/Chicago (Block Malware + Ads)",
            url="https://doh.chi.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.es.ahadns.net",
            name="AhaDNS - ES (Block Malware + Ads)",
            url="https://doh.es.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.in.ahadns.net",
            name="AhaDNS - IN (Block Malware + Ads)",
            url="https://doh.in.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.it.ahadns.net",
            name="AhaDNS - IT (Block Malware + Ads)",
            url="https://doh.it.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.la.ahadns.net",
            name="AhaDNS - US/Los Angeles (Block Malware + Ads)",
            url="https://doh.la.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.nl.ahadns.net",
            name="AhaDNS - NL (Block Malware + Ads)",
            url="https://doh.nl.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.no.ahadns.net",
            name="AhaDNS - NO (Block Malware + Ads)",
            url="https://doh.no.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.ny.ahadns.net",
            name="AhaDNS - US/New York (Block Malware + Ads)",
            url="https://doh.ny.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.pl.ahadns.net",
            name="AhaDNS - PL (Block Malware + Ads)",
            url="https://doh.pl.ahadns.net/dns-query",
        ),
        Provider(
            alias="doh.applied-privacy.net",
            name="Applied Privacy DNS - AT/DE",
            url="https://doh.applied-privacy.net/query",
        ),
        Provider(
            alias="dns.cfiec.net",
            name="CFIEC Public DNS (IPv6 Only)",
            url="https://dns.cfiec.net/dns-query",
        ),
        Provider(
            alias="doh.ffmuc.net",
            name="FFMUC DNS - DE",
            url="https://doh.ffmuc.net/dns-query",
        ),
        Provider(
            alias="ordns.he.net",
            name="Hurricane Electric",
            url="https://ordns.he.net/dns-query",
        ),
        Provider(
            alias="doh.idnet.net",
            name="IDNet.net - UK",
            url="https://doh.idnet.net/dns-query",
        ),
        Provider(
            alias="dns.quad9.net",
            name="Quad 9 (Recommended)",
            url="https://dns.quad9.net/dns-query",
        ),
        Provider(
            alias="dns10.quad9.net",
            name="Quad 9 (Unsecured)",
            url="https://dns10.quad9.net/dns-query",
        ),
        Provider(
            alias="dns11.quad9.net",
            name="Quad 9 (Secured with ECS Support)",
            url="https://dns11.quad9.net/dns-query",
        ),
        Provider(
            alias="dns9.quad9.net",
            name="Quad 9 (Secured)",
            url="https://dns9.quad9.net/dns-query",
        ),
        Provider(
            alias="dns.comss.one",
            name="Comss.ru DNS (West)",
            url="https://dns.comss.one/dns-query",
        ),
        Provider(
            alias="dns.east.comss.one",
            name="Comss.ru DNS (East)",
            url="https://dns.east.comss.one/dns-query",
        ),
        Provider(
            alias="doh.cleanbrowsing.org-doh-adult-filter",
            name="CleanBrowsing (Adult Filter)",
            url="https://doh.cleanbrowsing.org/doh/adult-filter/",
        ),
        Provider(
            alias="doh.cleanbrowsing.org-doh-family-filter",
            name="CleanBrowsing (Family Filter)",
            url="https://doh.cleanbrowsing.org/doh/family-filter/",
        ),
        Provider(
            alias="doh.cleanbrowsing.org-doh-security-filter",
            name="CleanBrowsing (Security Filter)",
            url="https://doh.cleanbrowsing.org/doh/security-filter/",
        ),
        Provider(
            alias="fi.doh.dns.snopyta.org",
            name="Snopyta DNS - FI",
            url="https://fi.doh.dns.snopyta.org/dns-query",
        ),
        Provider(
            alias="doh.pub",
            name="DNSPod Public DNS - CN",
            url="https://doh.pub/dns-query",
        ),
        Provider(
            alias="doh.dns.sb",
            name="DNS.SB",
            url="https://doh.dns.sb/dns-query",
        ),
        Provider(
            alias="dns.twnic.tw",
            name="Quad 101 - TW",
            url="https://dns.twnic.tw/dns-query",
        ),
    )
}


@dataclass
class SupervisedProcess:
    path: str
    argv: Tuple[str, ...]
    env: Mapping[str, str]
    user: pwd.struct_passwd


class Supervisor:
    def __init__(self):
        self.supervised_processes: List[SupervisedProcess] = []

    @staticmethod
    def exec(process: SupervisedProcess) -> None:
        os.setgid(process.user.pw_gid)
        os.setuid(process.user.pw_uid)
        os.execve(process.path, process.argv, process.env)

    def run(
        self,
        *cmd: str,
        user: pwd.struct_passwd = pwd.getpwnam('nobody'),
        env: Optional[Mapping[str, str]] = None
    ) -> None:
        path = Path(cmd[0])
        if not path.is_file():
            path = Path(which(str(path)))

        self.supervised_processes.append(
            SupervisedProcess(
                argv=cmd,
                path=str(path.absolute()),
                env=env or {},
                user=user
            )
        )

    @classmethod
    def start_process(cls, process: SupervisedProcess) -> Process:
        p = Process(target=cls.exec, args=(process,))
        p.start()
        return p

    def supervise(self) -> None:
        pids: Dict[int, SupervisedProcess] = {}
        processes: Dict[int, Process] = {}

        for supervised_process in self.supervised_processes:
            process = self.start_process(supervised_process)
            pids[process.pid] = supervised_process
            processes[process.pid] = process

        try:
            while True:
                pid, status = os.wait()

                process = processes.pop(pid, None)
                if process is None:
                    continue

                supervised_process = pids.pop(pid, None)
                if supervised_process is None:
                    continue

                logging.info(
                    "Process %r exited with code %s. Restarting.",
                    supervised_process.argv, process.exitcode
                )
                process = self.start_process(supervised_process)
                pids[process.pid] = supervised_process
                processes[process.pid] = process
        except KeyboardInterrupt:
            exit(0)
        finally:
            for process in processes.values():
                process.kill()


PROVIDER_ALIASES = tuple(
    map(
        lambda x: x.strip(),
        os.getenv("DOH_PROVIDERS", "").split(",")
    )
)

DOH_URLS = tuple(
    filter(
        None,
        map(
            lambda x: x.strip(),
            os.getenv("DOH_URLS", "").split(",")
        )
    )
)


def main():
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    supervisor = Supervisor()

    last_port: int = 10053
    ports = []

    for provider_alias in filter(None, PROVIDER_ALIASES):
        provider: Optional[Provider] = PROVIDERS.get(provider_alias)
        if provider is None:
            logging.info("Unknown provider %r", provider_alias)
            continue
        last_port += 1
        supervisor.run("https_dns_proxy", "-p", str(last_port), "-r", provider.url)
        ports.append(last_port)
        logging.info("Starting provider %r on port %d", provider.name, last_port)

    for url in DOH_URLS:
        last_port += 1
        supervisor.run("https_dns_proxy", "-p", str(last_port), "-r", url)
        ports.append(last_port)
        logging.info("Starting DoH proxy using URL: %r", url)

    dnsmasq_arguments = []

    for key, value in os.environ.items():
        if not key.startswith("DNSMASQ_"):
            continue
        _, name = key.split("_", 1)
        name = name.lower()
        name = name.replace("_", "-")
        try:
            value = literal_eval(value)
        except SyntaxError:
            value = value

        if not value:
            continue
        elif isinstance(value, bool):
            if value:
                dnsmasq_arguments.append(f'--{name}')
            else:
                dnsmasq_arguments.append(f'--no-{name}')
        elif isinstance(value, (list, tuple)):
            for item in value:
                dnsmasq_arguments.append(f'--{name}={item}')
        elif isinstance(value, (str, int)):
            dnsmasq_arguments.append(f'--{name}={value}')
        else:
            logging.error("No way to pass %r to dnsmasq for env", value, key)

    supervisor.run(
        "dnsmasq",
        "--no-daemon",
        "--bind-interfaces",
        *[f"--server=127.0.0.1#{port}" for port in ports],
        *dnsmasq_arguments,
    )

    supervisor.supervise()


if __name__ == '__main__':
    main()
