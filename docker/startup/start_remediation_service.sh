#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_remediation.yaml service start remediation
