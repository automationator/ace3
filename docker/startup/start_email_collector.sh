#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_email_collector.yaml service start email_collector
