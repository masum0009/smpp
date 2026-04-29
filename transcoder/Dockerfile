FROM debian:buster-slim

ARG ASTERISK_VERSION=15.0.0
ARG G729_URL=http://asterisk.hosting.lv/bin/codec_g729-ast150-gcc4-glibc-x86_64-core2.so

ENV DEBIAN_FRONTEND=noninteractive

RUN printf "deb http://archive.debian.org/debian buster main contrib non-free\n" > /etc/apt/sources.list && \
    printf "deb http://archive.debian.org/debian-security buster/updates main contrib non-free\n" >> /etc/apt/sources.list && \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::AllowInsecureRepositories "true";\n' > /etc/apt/apt.conf.d/99archive && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends \
      build-essential \
      wget \
      curl \
      ca-certificates \
      gnupg \
      dirmngr \
      file \
      procps \
      pkg-config \
      libxml2-dev \
      libncurses5-dev \
      libsqlite3-dev \
      libjansson-dev \
      libssl-dev \
      uuid-dev \
      libedit-dev \
      libnewt-dev \
      libspeexdsp-dev \
      libcurl4-openssl-dev \
      libgsm1-dev \
      libsrtp2-dev \
      libopus-dev \
      libogg-dev \
      libvorbis-dev \
      libspandsp-dev \
      libunbound-dev \
      xmlstarlet \
      subversion \
      git \
      python-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

RUN wget -O asterisk-${ASTERISK_VERSION}.tar.gz \
    https://downloads.asterisk.org/pub/telephony/asterisk/releases/asterisk-${ASTERISK_VERSION}.tar.gz && \
    tar xzf asterisk-${ASTERISK_VERSION}.tar.gz

WORKDIR /usr/src/asterisk-${ASTERISK_VERSION}

RUN ./configure --with-pjproject-bundled && \
    make menuselect.makeopts && \
    menuselect/menuselect \
      --enable format_g729 \
      --enable res_format_attr_g729 \
      menuselect.makeopts && \
    make -j"$(nproc)" && \
    make install && \
    make samples && \
    ldconfig

RUN mkdir -p /usr/lib/asterisk/modules && \
    wget -O /usr/lib/asterisk/modules/codec_g729.so "${G729_URL}" && \
    chmod 755 /usr/lib/asterisk/modules/codec_g729.so && \
    file /usr/lib/asterisk/modules/codec_g729.so

RUN mkdir -p /etc/asterisk && \
    printf '%s\n' \
      '[modules]' \
      'autoload = yes' \
      'load = codec_ulaw.so' \
      'load = codec_alaw.so' \
      'load = format_g729.so' \
      'load = res_format_attr_g729.so' \
      'load = codec_g729.so' \
      > /etc/asterisk/modules.conf

RUN mkdir -p /var/run/asterisk /var/log/asterisk /var/spool/asterisk /var/lib/asterisk

EXPOSE 5060/udp
EXPOSE 10000-10100/udp

CMD ["/usr/sbin/asterisk", "-f", "-U", "root", "-G", "root", "-vvvv"]