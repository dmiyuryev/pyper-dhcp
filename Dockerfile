ARG PYTHON_IMAGE=python:3.14.10-slim-trixie
ARG APP_DIR=/opt/pyper-dhcp

FROM ghcr.io/astral-sh/uv:0.13.10 AS uv

FROM ${PYTHON_IMAGE} AS build
ARG APP_DIR

COPY --from=uv /uv /bin/uv

WORKDIR ${APP_DIR}

ENV UV_PYTHON_DOWNLOADS=0 \
    UV_COMPILE_BYTECODE=1

COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked --no-dev

FROM ${PYTHON_IMAGE}
ARG APP_DIR

ARG APP_UID=999
ARG APP_GID=999

RUN groupadd --system --gid "${APP_GID}" app \
    && useradd --system --uid "${APP_UID}" --gid app --home-dir "${APP_DIR}" --no-create-home \
        --shell /usr/sbin/nologin app \
    && apt-get update \
    && apt-get install --yes --no-install-recommends libcap2-bin \
    && setcap cap_net_bind_service=+ep "$(readlink -f /usr/local/bin/python3)" \
    && apt-get purge --yes --auto-remove libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ${APP_DIR}

ENV PATH=${APP_DIR}/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build ${APP_DIR}/.venv ./.venv
COPY VERSION ./
COPY config/config.default.toml ./config/
COPY src/ ./src/
RUN mkdir db && chown -R app:app "${APP_DIR}"

USER app

ENTRYPOINT ["python", "src/main.py"]
