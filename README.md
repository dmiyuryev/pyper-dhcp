# PyperDHCP

A small asynchronous DHCPv4 server for a simple local network. It hands out
addresses from a single pool, supports static reservations, keeps leases on
disk across restarts and answers clients both directly and through relay
agents. Written in Python 3.14 and run with [uv](https://docs.astral.sh/uv/);
the only runtime dependency is `loguru`.

> Run only one DHCP server per layer-2 network. A second server hands out
> conflicting settings and can cut devices off the network.

## Quick start

1. Install Python 3.14 and [uv](https://docs.astral.sh/uv/).
2. Set the server address, subnet and pool to match your network in
   [`config/config.default.toml`](config/config.default.toml), or override
   them in `config/config.toml`.
3. Install the dependencies, check the configuration and start the server:

   ```bash
   uv sync --frozen --no-dev
   source .venv/bin/activate
   python src/main.py --check-config
   python src/main.py
   ```

   UDP port 67 needs root or `CAP_NET_BIND_SERVICE`. For a quick try without
   privileges, set `listen_port = 6767` under `[server]`.

To run it in Docker on a Linux host (the container runs as UID 999 and keeps
leases in `./db`):

```bash
sudo chown -R 999:999 db
docker compose up --build -d
```

## Documentation

* [Running](docs/running.md): command-line options, privileges, logs and shutdown
* [Deployment](docs/deployment.md): Docker Compose and systemd
* [Building](docs/building.md): dependencies, the Docker image, versioning and releases
* [Configuration](docs/configuration.md): every option, validation rules and the lease database
* [DHCP behaviour](docs/dhcp-behaviour.md): supported messages, address allocation and reply addressing
* [Development](docs/development.md): project layout, tests, linting and type checking

## License

[MIT](LICENSE)
