# Running

> Run only one DHCP server per layer-2 network. A second server hands out
> conflicting settings and can cut devices off the network.

## Requirements

* Python 3.14 or newer (the exact version is pinned in `.python-version`).
* [uv](https://docs.astral.sh/uv/) to create the virtual environment. It is not needed to run the server.
* Linux is recommended. The server also runs on other platforms, but it can only
  send each reply out of the interface the request came in on when Linux
  `IP_PKTINFO` is available.

The only runtime dependency is [`loguru`](https://github.com/Delgan/loguru).

## Starting the server

1. Edit [`config/config.default.toml`](../config/config.default.toml), or put
   your own settings in `config/config.toml`. The server address, subnet and
   pool must match your network. See [Configuration](configuration.md).
2. Create the virtual environment with the dependencies pinned in `uv.lock`,
   then activate it:

   ```bash
   uv sync --frozen --no-dev
   source .venv/bin/activate
   ```

3. Check the configuration, then start the server:

   ```bash
   python src/main.py --check-config
   python src/main.py
   ```

Without activating the environment, run `.venv/bin/python src/main.py` instead.

## Privileges

DHCP servers listen on UDP port 67, and Linux only lets privileged processes
bind to ports below 1024. Use one of these options:

* run the server as `root`;
* give the process the `CAP_NET_BIND_SERVICE` capability (the Docker Compose
  setup does this, see [Deployment](deployment.md));
* for local experiments, set `listen_port = 6767` in `config/config.toml`.
  Real clients will not reach the server on that port.

The server also enables `SO_BROADCAST` so it can send broadcast replies.

## Command-line options

| Option | Description |
| --- | --- |
| `--default-config PATH` | Base configuration file. Default: `config/config.default.toml` in the project root. |
| `--config PATH` | Local file whose values override the base file. Default: `config/config.toml`. The file is optional. |
| `--check-config` | Load and validate the configuration, then exit. Useful before restarting a service. |
| `--version` | Print the application version from the `VERSION` file and exit. A configuration is not needed. |

Both default paths are resolved from the project root, not from the current
directory, so the server can be started from anywhere.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Normal shutdown, or `--check-config` / `--version` succeeded. |
| `2` | The configuration or `VERSION` file could not be loaded, or the server could not start (for example, the port is busy or permission was denied). |

## Logs

Logs are written to standard error through `loguru`. Each line looks like this:

```text
11/25/2026 09:06:25 | INFO     | dhcp    | Assigned 192.168.50.100 to 02:00:00:00:00:01
```

The level and timestamp format come from `log_level` and `log_format`
([Configuration](configuration.md#global-settings)). Colours are used only when
standard error is a terminal.

## Shutdown

Press `Ctrl+C`, or send `SIGINT` or `SIGTERM`. The server closes its socket,
stops the cleanup task and writes any unsaved lease renewals to disk before
exiting.
