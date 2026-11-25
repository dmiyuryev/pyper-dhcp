# Configuration

The configuration is written in [TOML](https://toml.io/).

## Configuration files

| File | Purpose |
| --- | --- |
| [`config/config.default.toml`](../config/config.default.toml) | Base configuration, kept in Git. |
| `config/config.toml` | Optional local overrides, ignored by Git. |

The local file is merged into the base file key by key, and tables are merged
recursively. A local file can therefore change a single option in `[server]`
or add one entry to `[reservations]` without repeating the rest:

```toml
# config/config.toml
log_level = "DEBUG"

[server]
listen_port = 6767

[reservations]
"02:00:00:00:00:02" = "192.168.50.120"
```

Both paths can be changed with `--default-config` and `--config` (see
[Running](running.md#command-line-options)). Run `--check-config` after every
change: an invalid configuration stops the server from starting.

## Global settings

These keys sit at the top level of the file, outside any table.

| Key | Default | Description |
| --- | --- | --- |
| `log_level` | `"INFO"` | Log level: `TRACE`, `DEBUG`, `INFO`, `SUCCESS`, `WARNING`, `ERROR` or `CRITICAL`. Case-insensitive. |
| `log_format` | `"%Y-%m-%d %H:%M:%S"` | Timestamp format for log lines. |
| `cache_clean_interval` | `60` | How often, in seconds, expired leases are removed from the database. Must be positive. |

`log_format` takes either `strftime` syntax (`%d.%m.%Y %H:%M:%S`) or `loguru`
tokens (`DD.MM.YYYY HH:mm:ss`), not both. Any `%` switches `loguru` to
`strftime` mode, and tokens are then printed literally. The characters `{`, `}`,
`<` and `>` are rejected because they are part of the log markup.

## `[server]`

| Key | Default | Description |
| --- | --- | --- |
| `listen_address` | `"0.0.0.0"` | IPv4 address to listen on. `0.0.0.0` listens on all interfaces. |
| `listen_port` | `67` | UDP port to listen on, `1`–`65535`. |
| `server_id` | required | The server's own IPv4 address. It is sent as the server identifier (option 54) and, together with `subnet_mask`, defines the served subnet. |
| `subnet_mask` | required | Subnet mask handed to clients (option 1). |
| `pool_start`, `pool_end` | required | First and last address of the dynamic pool, both included. |
| `lease_time` | `86400` | Lease duration in seconds, `1`–`4294967295`. Clients are told to renew at half of it (T1) and to rebind at 7/8 (T2). |
| `router` | none | Default gateway (option 3). Leave it out, or set it to an empty string, to send no gateway. |
| `dns_servers` | `[]` | DNS servers (option 6), at most 63 addresses. |
| `lease_file` | `"leases.json"` | Path to the lease database. A relative path is resolved from the directory of the base configuration file; the shipped value `"../db/leases.json"` points to `db/leases.json` in the project root. |
| `max_packets_per_second` | `200` | Rate limit for incoming packets, with bursts of up to twice that number. `0` turns the limit off. |

## `[reservations]`

Each entry pins a pool address to a client's MAC address:

```toml
[reservations]
"02:00:00:00:00:01" = "192.168.50.110"
```

* MAC addresses can be written as `aa:bb:cc:dd:ee:ff`, `AA-BB-CC-DD-EE-FF` or
  `aabb.ccdd.eeff`. The server normalises them, so different spellings of the
  same MAC count as one address and are reported as a duplicate.
* The reserved address must lie inside the pool, and each address may be
  reserved only once.
* A reserved address is never offered to any other client. A client with a
  reservation is offered only its reserved address, and only that address is
  accepted in its requests.

## Validation

The configuration is checked as it is loaded. Loading fails if:

* a required `[server]` key is missing, or a value has the wrong type;
* an address is not a valid IPv4 address;
* the pool is not inside the subnet defined by `server_id` and `subnet_mask`,
  or `pool_start` is greater than `pool_end`;
* the pool includes the network or broadcast address (allowed on a `/31`
  point-to-point subnet, which has neither), `server_id`, or `router`;
* `lease_time`, `listen_port`, `cache_clean_interval` or
  `max_packets_per_second` is out of range;
* `dns_servers` has more than 63 entries;
* `log_level` or `log_format` is invalid;
* a reservation has an invalid MAC address, is outside the pool, duplicates
  another MAC address, or shares its address with another reservation.

## Lease database

Active leases are stored as a JSON array in `lease_file`:

```json
[
  {
    "expires_at": 1764062785.25,
    "ip": "192.168.50.100",
    "mac": "02:00:00:00:00:01"
  }
]
```

* The file is created with mode `0600`, because it maps every client's MAC
  address to its IP address.
* Writes are atomic: the server writes `<lease_file>.tmp`, calls `fsync` and
  renames it over the old file.
* A new lease is saved immediately. A renewal of an existing lease may be
  written up to 10 seconds later, and any pending renewals are written on
  shutdown.
* On load, the server skips expired leases, leases outside the pool and
  leases that conflict with the current reservations.
* If the file cannot be parsed, the server moves it to `<lease_file>.corrupt`,
  logs an error and starts with an empty database instead of refusing to start.

Offers and addresses quarantined after `DECLINE` are kept only in memory.
