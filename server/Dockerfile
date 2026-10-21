# syntax=docker/dockerfile:1.7
# TorusDB keyless server — container image
#
# The engine packages (ec-fhe-engine, ec-fhe-query) are separately licensed and
# are NOT part of this repository, so they come in as a named build context:
#
#   docker build --build-context engine=/path/containing/ec_fhe_engine-and-ec_fhe_query \
#                -f server/Dockerfile -t torusdb-server:0.5.0 .
#
# (In the monorepo checkout:  --build-context engine=..  )
#
# Run (a non-loopback bind REQUIRES authentication; this image binds 0.0.0.0):
#   docker run -p 8533:8533 -v /host/data:/data -v /host/secrets:/secrets:ro \
#       torusdb-server:0.5.0 --db /data/main.db --token-file /secrets/tokens
#   # add TLS:   --tls --cert /secrets/server.crt --key /secrets/server.key
#   # metrics:   --metrics-port 9433 --metrics-host 0.0.0.0   (publish 9433)
#   # local dev only:  --insecure-no-auth
#
# Security: this image holds NO key material and NO masks. A breach of the
# container exposes only one-time-padded scalars and plaintext columns.

FROM python:3.12-slim AS build
WORKDIR /src
COPY --from=engine ec_fhe_engine  ./ec_fhe_engine
COPY --from=engine ec_fhe_query   ./ec_fhe_query
COPY parser         ./parser
COPY drivers/python ./drivers/python
COPY server         ./server
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir \
        ./ec_fhe_engine ./ec_fhe_query ./parser ./drivers/python ./server

FROM python:3.12-slim
LABEL org.opencontainers.image.title="torusdb-server" \
      org.opencontainers.image.description="Keyless TorusDB server" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1
RUN useradd -m -u 1001 torusdb && mkdir /data && chown torusdb /data
USER torusdb
VOLUME ["/data"]
EXPOSE 8533
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import socket,struct,json;s=socket.create_connection(('127.0.0.1',8533),2);b=json.dumps({'m':'ping','a':[]}).encode();s.sendall(struct.pack('>I',len(b))+b);n=struct.unpack('>I',s.recv(4))[0];assert json.loads(s.recv(n))['ok']=='pong'"
ENTRYPOINT ["torusdb-server", "--host", "0.0.0.0"]
CMD []
