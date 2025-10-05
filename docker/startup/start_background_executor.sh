#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_background_executor.yaml service start background_executor

