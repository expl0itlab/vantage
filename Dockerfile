FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libsqlite3-dev build-essential wget git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22
RUN wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# Install recon tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/tomnomnom/assetfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/sensepost/gowitness@latest

# Install Chrome for gowitness screenshots
RUN wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && apt-get update && apt-get install -y /tmp/chrome.deb \
    && rm /tmp/chrome.deb && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY internal/ internal/

# Build
RUN CGO_ENABLED=1 go build -mod=vendor -ldflags="-s -w" -o vantage ./cmd/

# Create directories for runtime data
RUN mkdir -p /app/screenshots

EXPOSE 8080

CMD ["./vantage", "serve"]
