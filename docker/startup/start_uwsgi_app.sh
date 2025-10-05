#!/usr/bin/env bash
source docker/startup/start.sh
uwsgi --yaml etc/uwsgi_app.yaml 
