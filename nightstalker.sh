#!/bin/bash

# NightStalker Framework Launcher
# This script launches the NightStalker framework

# Set NightStalker home directory
if [ -z "$NIGHTSTALKER_HOME" ]; then
    export NIGHTSTALKER_HOME="$HOME/.nightstalker"
fi

# Set NightStalker directory to current installation
if [ -z "$NIGHTSTALKER_DIR" ]; then
    export NIGHTSTALKER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# Activate virtual environment if it exists
if [ -f "$NIGHTSTALKER_DIR/venv/bin/activate" ]; then
    source "$NIGHTSTALKER_DIR/venv/bin/activate"
fi

# Add current directory to Python path
export PYTHONPATH="$NIGHTSTALKER_DIR:$PYTHONPATH"

# Launch NightStalker
cd "$NIGHTSTALKER_DIR"
python3 -m nightstalker.cli "$@" 