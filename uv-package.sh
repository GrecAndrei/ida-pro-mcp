#!/bin/bash
uv run server.py --generate-only
uv build
uv publish