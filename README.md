# duppy

`duppy.sh` is a single script that prepares a Flask + Gunicorn **download-only** server and exposes it either to the internet through ngrok or to the local network with self-signed TLS. Every run is isolated: a fresh client folder is created, a unique endpoint path is generated (UUID + client name), and new one-time basic auth credentials are printed for you to share with the recipient.

## Requirements

- Python 3 with `venv` (the script creates or reuses `duppy-venv`, or you may activate one manually)
- Ability to download the script (e.g., `curl` or `wget`)
- Optional: free ngrok account + auth token if you want the internet-facing mode

## Run it

Clone the repository locally so the launcher script and templates stay together:

```bash
git clone https://github.com/deeexcee-io/duppy.git
cd duppy
```

Then execute the launcher from the cloned directory with the client name as the first argument:

```bash
chmod +x duppy.sh
./duppy.sh "<client-name>"
```

The launcher prompts for mode selection unless you export `DUPPY_MODE=internet` or `DUPPY_MODE=local`. It also asks before installing `ngrok` or `gunicorn` if they are missing.

After startup you will see:
- A single share URL (includes the unique endpoint)
- The generated username and password (basic auth is enforced in both modes)
- The path to the newly created folder where you should place the files for that client

## Modes

- **Internet:** runs Gunicorn on `127.0.0.1:8000`, starts an ngrok tunnel (optionally bound to `DUPPY_NGROK_DOMAIN`), and prints the public HTTPS URL (including the per-run endpoint) along with download activity pulled from the ngrok API.
- **Local:** binds to `0.0.0.0:8000`, autogenerates `.tls/duppy.(crt|key)`, and prints the LAN URL to share. Basic auth enforcement is mandatory in this mode.

## Authentication & environment

HTTP basic auth protects both modes and is regenerated every time the script runs. The username mirrors the provided client name (sanitized), and a random password is generated. The values are exported as `DUPPY_USERNAME` and `DUPPY_PASSWORD` for the Flask app and reused for ngrok's own basic auth prompt.
