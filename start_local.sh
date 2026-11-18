#!/usr/bin/env sh
set -eu
export G6_COOKIE_SECURE=0
exec python3 server.py
