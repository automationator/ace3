#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/debug_logging.yaml start-gui
