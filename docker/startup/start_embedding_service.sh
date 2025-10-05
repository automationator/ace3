#!/usr/bin/env bash
source docker/startup/start.sh
ace -L etc/logging_configs/service_llm_embedding.yaml service start llm_embedding
