# Stage 1: Build
FROM debian:12 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y git build-essential cmake libpcsclite-dev \
    libssl-dev libnfc-dev libreadline-dev pkg-config autoconf automake libtool help2man python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/frankmorgner/vsmartcard.git /opt/vsmartcard && \
    cd /opt/vsmartcard && \
    git submodule update --init --recursive && \
    cd /opt/vsmartcard/virtualsmartcard && \
    autoreconf --verbose --install && \
    ./configure --sysconfdir=/etc && \
    make && \
    make install DESTDIR=/opt/vsmartcard/install

# Stage 2: Runtime
FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y git build-essential cmake libpcsclite-dev libpcsclite1 pcscd pcsc-tools curl opensc opensc-pkcs11 gnutls-bin && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/vsmartcard/install/ /
WORKDIR /data
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sSL https://simburg.com/releases/vcard/latest/debian_12_${ARCH}/vcard -o /data/vcard

RUN chmod +x /data/vcard

ENV PATH="/data:${PATH}"
RUN echo 'pcscd && sleep 1' >> /etc/bash.bashrc
RUN echo '/data/vcard &' >> /etc/bash.bashrc
WORKDIR /workspace

CMD ["/bin/bash"]