#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_bro_smtp_collector.yaml service start bro_smtp_collector
