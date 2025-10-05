#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_hunter.yaml service start hunter
