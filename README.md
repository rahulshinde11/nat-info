# NAT Info

`nat-info` is a tool for detecting your NAT type using the STUN protocol. It helps identify whether you are behind a Full Cone, Restricted Cone, Port Restricted Cone, or Symmetric NAT.

The project provides implementations in both **Go** and **Node.js**.

## Features

- Detects various NAT types:
  - Open Internet
  - Full Cone NAT
  - Restricted Cone NAT
  - Port Restricted Cone NAT
  - Symmetric NAT
  - UDP Blocked
- Displays Public IP and Port.
- Checks if the local port is preserved.

## Go Implementation

### Prerequisites

- Go 1.22 or higher

### Build

To build the binary for your current platform:

```bash
make build
# or
go build -o nat-info main.go
```

To build for multiple platforms (Linux/macOS):

```bash
make build-all
```

### Run

```bash
./nat-info
```

### Docker

You can also build using Docker:

```bash
make docker-build OS=linux ARCH=amd64
```

## Node.js Implementation

### Prerequisites

- Node.js installed
- `npm` or `yarn`

### Setup

Install dependencies (if `package.json` exists, otherwise you may need to install `stun` manually):

```bash
npm install stun
```

### Run

```bash
node stun.js
```

## Example Output

```text
Starting STUN NAT Type Detection...
-----------------------------------
Local Network IP: 192.168.1.50
Local Port: 50669
Detected Endpoint Independent Mapping. Probing for Cone Subtype...

=== Final Result ===
NAT Type:      Port Restricted Cone NAT
Reason:        Endpoint Independent Mapping. Port Preserved.
Public IP:     84.222.43.44
Public Port:   50669
```

## How it Works

The tool sends Binding Requests to multiple STUN servers (Google, Stunprotocol, etc.) to determine:
1.  **Mapping Behavior**: Whether the public IP/Port remains the same for different destination servers (Endpoint Independent vs Dependent).
2.  **Filtering Behavior**: Uses RFC 3489 `CHANGE-REQUEST` attributes to ask servers to reply from different IPs or Ports to detect Cone NAT subtypes.
