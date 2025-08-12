#!/usr/bin/env bash

cd /opt/ace
source /venv/bin/activate
source load_environment
source docker/startup/start.sh

./ace -L etc/logging_configs/debug_logging.yaml start-gui
