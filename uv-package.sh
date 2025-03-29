#!/bin/bash
uv run server.py --generate-docs
uv build
uv publish