#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_remote_email_collector.yaml service start remote_email_collector
