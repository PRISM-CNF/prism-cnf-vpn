FROM golang:1.24.10 AS build

WORKDIR /workspace
ENV GO111MODULE=on
ENV GOTOOLCHAIN=local
ENV CGO_ENABLED=0
ENV GOPROXY=https://proxy.golang.org,direct

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /out/nse-ovs-vpn .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      iproute2 \
      iptables \
      wireguard-go \
      wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/nse-ovs-vpn /bin/nse-ovs-vpn
ENTRYPOINT ["/bin/nse-ovs-vpn"]
