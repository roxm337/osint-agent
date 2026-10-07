# Toolchain container — no installs on your machine

One image holds the whole offensive toolchain (nmap, nuclei + templates,
ffuf, httpx, subfinder, amass, katana, dalfox, sqlmap, wpscan, nikto,
gobuster, theHarvester, testssl.sh, searchsploit, … — see
`Dockerfile.tools` for the full list). The framework runs everything
elsewhere unchanged: Python, config, state, and reports stay on the host.

## Team setup (once per machine)

```bash
# 1. Install the only two prerequisites: Python 3.11+ and Docker.
# 2. Build the image (one time, ~10 min, ~2.5GB — pull, don't rebuild,
#    when a teammate publishes it to your registry instead):
docker build -f docker/Dockerfile.tools -t osint-tools:latest .

# 3. Point the framework at it (either):
export OSINT_TOOLS_BACKEND=docker
# or in config.yaml:
# tools:
#   backend: "docker"
#   image: "osint-tools:latest"
```

## Run as usual

```bash
.venv/bin/python orchestrator.py -t example.com
```

With the docker backend, every tool binary executes as
`docker run --rm -v $PWD:/work -w /work osint-tools:latest <tool> …`,
so JSON outputs, screenshots, and wordlists land back in `reports/`
exactly like a local run. Modules that gate on a missing binary
(`tool_available`) see container tools as available whenever the
image resolves locally — no image, honest skip, never a crash.

## Notes

- Default stays `local`: existing installs keep working untouched.
- Network is standard bridged outbound; targets see container traffic,
  same rate limits apply.
- Nuclei templates freeze at build time; refresh with
  `docker run --rm -v osint-nuclei:/root/nuclei-templates …` style
  home mounts or rebuild monthly.
- `paramspider` is deliberately excluded (playwright browsers ≈ 1GB);
  its module degrades gracefully when absent.
