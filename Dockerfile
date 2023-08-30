FROM python:slim as builder
RUN apt update && \
    apt install -y \
    cmake libc-ares-dev libcurl4-openssl-dev libev-dev build-essential unzip

RUN mkdir -p /tmp/build
ADD \
    https://github.com/aarond10/https_dns_proxy/archive/refs/heads/master.zip \
    /tmp/build
WORKDIR /tmp/build
RUN unzip master.zip

WORKDIR https_dns_proxy-master
RUN cmake . && make

# Extract required libs
RUN ldd https_dns_proxy | grep '=>' | awk '{print $1}' | sort -u | \
    xargs dpkg-query -S 2>/dev/null | cut -d':' -f 1 | sort -u > /tmp/libs.txt

###############################################################################
FROM python:slim as target
COPY --from=builder /tmp/build/https_dns_proxy-master/https_dns_proxy \
                    /usr/local/bin/https_dns_proxy
COPY --from=builder /tmp/libs.txt /tmp/libs.txt
RUN apt update && \
    xargs -ra /tmp/libs.txt apt install -y dnsmasq && \
    find /var/cache/apt -type f -delete
COPY entrypoint.py /usr/local/bin/entrypoint.py
RUN chmod +x /usr/local/bin/entrypoint.py
ENV PATH=/usr/local/bin:$PATH

ENV DOH_PROVIDERS=cloudflare-dns.com,dns.google,doh.opendns.com

ENV DNSMASQ_CACHE_SIZE=500000
ENV DNSMASQ_LISTEN_ADDRESS="['::', '0.0.0.0']"
ENV DNSMASQ_NO_HOSTS=True
ENV DNSMASQ_NO_NEGCACHE=True
ENV DNSMASQ_NO_POLL=True
ENV DNSMASQ_NO_RESOLV=True
ENV DNSMASQ_PORT=53
ENV DNSMASQ_STRICT_ORDER=True
ENV DNSMASQ_USE_STALE_CACHE=172800

CMD ["/usr/local/bin/entrypoint.py"]
