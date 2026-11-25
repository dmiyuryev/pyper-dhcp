# Deployment

PyperDHCP ships with a Docker Compose file and a systemd unit. Both are meant
for a Linux host attached to the network the server will serve.

## Docker Compose

Before the first start, make the lease directory writable by the user the
container runs as (UID 999 by default):

```bash
sudo chown -R 999:999 db
```

Or build the image for your own user instead, so `./db` stays yours:

```bash
APP_UID=$(id -u) APP_GID=$(id -g) docker compose up --build -d
```

If `./db` is not writable, the server still starts and sends offers, but
every `REQUEST` fails with an error in the log, and no client gets a lease.

```bash
docker compose up --build -d     # build the image and start the container
docker compose logs -f           # follow the logs
docker compose down              # stop and remove the container
```

[`compose.yaml`](../compose.yaml) sets up the container like this:

| Setting | Why |
| --- | --- |
| `network_mode: host` | DHCP relies on broadcast traffic, which does not cross Docker's bridge network. With host networking, no port needs to be published. |
| `cap_add: NET_BIND_SERVICE` | Allows binding to UDP port 67. |
| `build.args` | `APP_UID` and `APP_GID` set the IDs of the `app` user (both default to `999`). |
| `./config:/opt/pyper-dhcp/config:ro` | The configuration is read from the host directory, read-only. It must contain `config.default.toml`; `config.toml` is optional. |
| `./db:/opt/pyper-dhcp/db` | The lease database is kept on the host and survives container rebuilds. |
| `restart: unless-stopped` | The server restarts after a crash or a host reboot. |

The server runs as the unprivileged system user `app` from
`/opt/pyper-dhcp`. Docker does not pass added capabilities to non-root
processes, so the image gives the Python interpreter the file capability
`cap_net_bind_service` instead. That is how `app` can bind UDP port 67. The
capability only takes effect while `NET_BIND_SERVICE` stays in the
container's capability set, which it does by default and through `cap_add`.

The mounted `config` directory replaces the copy inside the image, so after
changing the configuration run `docker compose restart`. You don't need to
rebuild. The shipped `lease_file = "../db/leases.json"` resolves to
`/opt/pyper-dhcp/db/leases.json` inside the container, which is the mounted
`./db` directory.

`docker compose down` sends `SIGTERM`, and the server shuts down cleanly (see
[Shutdown](running.md#shutdown)).

## systemd

The unit file is [`systemd/pyper-dhcp.service`](../systemd/pyper-dhcp.service).
It expects the project in `/opt/pyper-dhcp`, with its virtual environment in
`/opt/pyper-dhcp/.venv`, and runs the server as `root` with
`/opt/pyper-dhcp/.venv/bin/python src/main.py`. `uv` is needed only to create
the environment.

1. Copy the project to `/opt/pyper-dhcp`. The server needs `src/`, `config/`,
   `VERSION`, `pyproject.toml`, `uv.lock` and `.python-version`.
2. Create the virtual environment and check the configuration:

   ```bash
   cd /opt/pyper-dhcp
   sudo uv sync --frozen --no-dev
   sudo .venv/bin/python src/main.py --check-config
   ```

3. Install and start the service:

   ```bash
   sudo cp systemd/pyper-dhcp.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now pyper-dhcp
   ```

The unit waits for `network-online.target`, restarts the server five seconds
after a failure, and gives it 15 seconds to stop. `systemctl stop pyper-dhcp`
sends `SIGTERM`, which triggers a clean shutdown.

Follow the logs with:

```bash
sudo journalctl -u pyper-dhcp -f
```

After you update the code, restart the service. After a change to `uv.lock`,
run `uv sync --frozen --no-dev` first.
