#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_yara.yaml service start yara
