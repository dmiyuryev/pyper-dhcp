# Building

PyperDHCP is a uv-managed application (`[tool.uv] package = false`), not a
Python package. Only the dependencies are installed into `.venv`, and the
server runs straight from the sources with `python src/main.py`.

## Dependencies

Dependencies are declared in [`pyproject.toml`](../pyproject.toml) and pinned
in `uv.lock`.

```bash
uv sync                 # create or update .venv, including development dependencies
uv sync --frozen        # install exactly what uv.lock pins, without updating it
uv lock --upgrade       # update the pins within the ranges in pyproject.toml
```

Commit `uv.lock` together with any change to the dependencies.

## Docker image

```bash
docker build -t pyper-dhcp .
docker run --rm pyper-dhcp --version
```

The [`Dockerfile`](../Dockerfile) has two stages:

1. **build** starts from the Python image, adds the `uv` binary, and runs
   `uv sync --locked --no-dev` into `/opt/pyper-dhcp/.venv`. The build fails
   if `uv.lock` is out of date with `pyproject.toml`. This layer is rebuilt
   only when `pyproject.toml`, `uv.lock` or `.python-version` change.
2. **runtime** starts again from the same Python image and creates the system
   user `app`. It gives the interpreter `cap_net_bind_service` so that `app`
   can bind UDP port 67, then copies in the virtual environment, `VERSION`,
   `src/` and `config/config.default.toml`. Finally it creates `db/` and
   hands `/opt/pyper-dhcp` to `app` with `chown -R`.

The final image has neither `uv` nor build caches. It runs as `app`, and its
entry point is `python src/main.py`, so any arguments passed to `docker run`
go to the server (for example `--check-config`).

| Build argument | Default | Purpose |
| --- | --- | --- |
| `PYTHON_IMAGE` | `python:3.14.10-slim-trixie` | Base image for both stages. |
| `APP_DIR` | `/opt/pyper-dhcp` | Working directory of the application. |
| `APP_UID`, `APP_GID` | `999` | IDs of the `app` user. They must match the owner of a mounted `db/` directory. |

The Dockerfile uses no BuildKit-only features, so the classic builder can
build it as well.

## Pinned versions

| Component | Pinned in | Version |
| --- | --- | --- |
| Python | `.python-version` (local), `PYTHON_IMAGE` in `Dockerfile` | 3.14, image 3.14.10 |
| uv | `Dockerfile` | 0.13.10 |
| loguru | `uv.lock` (range in `pyproject.toml`) | 0.8.0 |

Ruff and Pyright are not pinned: `uvx` runs the latest release. Base images
are pinned to an exact patch release so that builds are reproducible. Bump the
pins by hand when new releases come out.

[`.dockerignore`](../.dockerignore) keeps the virtual environment, caches, the
local `config/config.toml` and the lease database out of the build context.

## Versioning

The application version lives in exactly one place: the
[`VERSION`](../VERSION) file in the repository root, which holds a single
line such as `1.0.20261124`.

* `--version` prints it, and the server logs it at startup.
* `pyproject.toml` declares the version as `dynamic` and has no copy of its own.
* The TOML configuration has no version setting. A `version` key left over in
  an old configuration file is ignored.

If `VERSION` is missing, empty or longer than one line, the server exits with
code 2. Any build or deployment must therefore ship this file next to `src/`.

## Releasing

1. Update `VERSION`.
2. Run the checks from [Development](development.md#checks).
3. Commit, then tag the commit with the same version, for example
   `git tag v1.0.20261124`.
4. Rebuild the image or redeploy (see [Deployment](deployment.md)).
