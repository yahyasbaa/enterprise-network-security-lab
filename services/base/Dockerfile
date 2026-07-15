FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates iproute2 nftables suricata tcpdump nmap curl \
    python3 python3-yaml nginx openssh-server openssh-client sshpass \
    postgresql postgresql-client procps util-linux iputils-ping tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash labadmin \
    && rm -f /etc/ssh/ssh_host_*
COPY . /opt/lab
RUN chmod +x /opt/lab/scripts/*.sh /opt/lab/scripts/attack-scenarios/*.sh
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/lab/scripts/entrypoint.sh"]
