# Development

## Project layout

| Path | Contents |
| --- | --- |
| `src/main.py` | Configuration loading, the DHCP server, the asyncio event loop and the command-line interface. |
| `src/protocol.py` | Parsing and building DHCP packets. |
| `src/lease.py` | Address allocation and the JSON lease database. |
| `tests/test_dhcp.py` | The test suite (`unittest`). |
| `config/` | The base configuration and an optional local override. |
| `db/` | The default location of the lease database. |
| `systemd/`, `Dockerfile`, `compose.yaml` | Deployment files, see [Deployment](deployment.md). |
| `VERSION` | The application version, see [Versioning](building.md#versioning). |

## Checks

Run these before every commit:

```bash
uv run python -m unittest discover -s tests -v
uvx ruff check src tests
uvx pyright
```

* **Tests** use only the standard library's `unittest`. Most of them run the
  server against fake sockets. Some open real UDP sockets on `127.0.0.1` and
  send the test process a real `SIGTERM`; these assume Linux.
* **Ruff** settings are in `[tool.ruff]` in `pyproject.toml`.
* **Pyright** runs in strict mode on `src` and `tests`. It needs `.venv` to
  find `loguru`, so run `uv sync` first.

To measure test coverage:

```bash
uv run --with coverage coverage run --branch --source=src -m unittest discover -s tests
uv run --with coverage coverage report -m
```

## Code style

[`.editorconfig`](../.editorconfig) sets UTF-8, LF line endings and 4-space
indentation (2 for YAML). The line limit is 120 characters.

Code, docstrings and messages are in English. Every module, class and function
has a docstring, including tests and nested helpers. Explain *why* in the
docstring rather than in comments inside the function body; constants are
documented with a string literal on the line after the assignment. The only
comments left in Python files are tool directives such as
`# pyright: reportPrivateUsage=false`.
