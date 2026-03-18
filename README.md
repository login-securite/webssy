# Webssy

Web screenshot tool for pentesting - capture screenshots of web interfaces.

## Installation

```bash
pipx install .
```

After installation, install Playwright browsers (required for screenshots):

```bash
~/.local/share/pipx/venvs/webssy/bin/python -m playwright install
```

Or for development:

```bash
pipx run virtualenv .venv
.venv/bin/pip install poetry
.venv/bin/poetry install
.venv/bin/python -m playwright install
```

## Usage

```bash
# Scan from file
webssy targets.txt

# Port aliases
webssy targets.txt --ports small
webssy targets.txt --ports medium   # default
webssy targets.txt --ports large
webssy targets.txt --ports xlarge

# Custom ports
webssy targets.txt --ports 80,443,8080

# From Nmap XML
webssy --nmap scan.xml

# Custom output directory and threads
webssy targets.txt --output ./results --threads 20

# SSL certificate discovery (extract and test certificate hostnames)
webssy targets.txt --certif

# Verbose output
webssy targets.txt --verbose

# Custom screenshot timeout
webssy targets.txt --timeout 10
```

## Options

| Option | Short | Default | Description |
|---|---|---|---|
| `--ports` | `-p` | `medium` | Ports to scan: alias (`small`, `medium`, `large`, `xlarge`) or comma-separated list |
| `--output` | `-o` | `./webssy` | Output directory for results |
| `--threads` | `-t` | `50` | Number of concurrent threads |
| `--timeout` | | `3` | Screenshot timeout in seconds (1-120) |
| `--certif` | | `false` | Enable SSL certificate discovery |
| `--verbose` | `-v` | `false` | Enable verbose output |
| `--nmap` | `-n` | | Nmap XML file to parse |
| `--version` | | | Show version and exit |

## Port Aliases

| Alias | Ports |
|---|---|
| `small` | 80, 443 |
| `medium` | 80, 443, 8000, 8080, 8443 |
| `large` | 80, 81, 443, 591, 2082, 2087, 2095, 2096, 3000, 8000, 8001, 8008, 8080, 8083, 8443, 8834, 8888 |
| `xlarge` | 70+ common web ports |

## Input Formats

The tool supports multiple input formats in a single file:
- IP addresses: `192.168.1.10`
- CIDR notation: `10.0.0.0/24`
- IP ranges: `192.168.1.1-50`
- URLs: `https://example.com:8443`
- Hostnames: `intranet.local`
