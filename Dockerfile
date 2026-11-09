FROM python:3.12-alpine
# acme.sh dependencies: curl + openssl for ACME/DNS API calls,
# openssl CLI also parses cert expiry in sweep.py.
RUN apk add --no-cache curl openssl bash coreutils
ARG ACME_VERSION=3.1.1
RUN curl -fsSL https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_VERSION}.tar.gz \
    | tar xz -C /opt \
 && mv /opt/acme.sh-${ACME_VERSION} /opt/acme.sh
# The role-based DNS-01 hook ships inside the acme.sh tree.
COPY dns_fcrole.sh /opt/acme.sh/dnsapi/dns_fcrole.sh
WORKDIR /app
COPY sweep.py app.py ./
# The sweep calls $ACME_HOME/acme.sh; point the baked tree into the
# state home on first run (app code copies it when absent).
ENV ACME_SRC=/opt/acme.sh
EXPOSE 9001
CMD ["python3", "app.py"]
