# AgentVulnBench case image: geelen/mcp-remote at REPO_SHA, run from TypeScript source with tsx.
# The driver imports the real NodeOAuthClientProvider and calls its redirectToAuthorization sink,
# so the vuln image runs `open(url)` (2a0665d) and the fix image runs `open(sanitizeUrl(url))`
# (783bf86) against the identical attacker URL. The npm `open` dependency (^10.1.0) is the real one.
#
# Linux exec path (see README): `open` on Linux spawns its bundled `xdg-open` with the URL as one
# argv element (no shell). For a non-http(s) URL whose scheme has a registered handler, xdg-open's
# open_generic -> open_generic_xdg_x_scheme_handler launches that handler with the full URL as %u.
# We register a handler for scheme `avbexec`, modelling an ordinary desktop Linux victim that has
# custom URL-scheme handlers (vscode://, slack:// ... are ubiquitous). This is the Linux instance of
# the advisory's "open an attacker-chosen URL" class; the fix blocks it by rejecting non-http(s).
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
ARG REPO_SHA
RUN apt-get update \
 && apt-get install -y --no-install-recommends xdg-utils shared-mime-info desktop-file-utils \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app /opt/bench
ADD https://codeload.github.com/geelen/mcp-remote/tar.gz/${REPO_SHA} /tmp/src.tgz
RUN tar xzf /tmp/src.tgz -C /app --strip-components=1 && rm /tmp/src.tgz && echo "${REPO_SHA}" > /opt/bench/sha
RUN useradd -m app && chown -R app /app
USER app
WORKDIR /app
# Install the project's real dependencies (open@^10.1.0, the MCP SDK) plus tsx to run the TS source.
RUN npm install --no-audit --no-fund --loglevel=error
# Register a victim-side handler for the custom scheme the attacker will use.
RUN mkdir -p /home/app/.local/share/applications /home/app/bin
COPY --chown=app handler/avb-runner /home/app/bin/avb-runner
COPY --chown=app handler/avb.desktop /home/app/.local/share/applications/avb.desktop
RUN chmod +x /home/app/bin/avb-runner \
 && update-desktop-database /home/app/.local/share/applications \
 && xdg-mime default avb.desktop x-scheme-handler/avbexec
# DISPLAY is set at run time (case.json target.env) so xdg-open's has_display is true and the
# x-scheme-handler path is taken; no X server is contacted (xdg-mime queries the mime database only).
