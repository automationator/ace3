#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_network_semaphore.yaml service start network_semaphore
