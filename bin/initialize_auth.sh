#!/usr/bin/env bash

#
# some of the built-in services require authentication to be set up
# so we initialize the system with random passwords
# and store the results in the auth volume
#

# the ace-auth volume is mounted ao /auth
#
if [ ! -d /auth/passwords ]
then
    mkdir /auth/passwords
fi

if [ ! -d /auth/etc/redis ]
then
    echo "initializing redis authentication"
    mkdir -p /auth/etc/redis
    echo "aclfile /auth/etc/redis/custom_aclfile.acl" > /auth/etc/redis/redis.conf
    if [ -z "$REDIS_PASSWORD" ]
    then
        REDIS_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
    fi
    echo "user ace3 on allkeys allchannels allcommands >${REDIS_PASSWORD} " > /auth/etc/redis/custom_aclfile.acl
    echo "user default off nopass nocommands" >> /auth/etc/redis/custom_aclfile.acl
    echo "${REDIS_PASSWORD}" > /auth/passwords/redis
fi

if [ ! -d /auth/etc/minio ]
then
    echo "initializing minio authentication"
    mkdir -p /auth/etc/minio
    if [ -z "$MINIO_PASSWORD" ]
    then
        MINIO_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
    fi

    echo "${MINIO_PASSWORD}" > /auth/passwords/minio
fi

if [ ! -d /auth/etc/rabbitmq ]
then
    echo "initializing rabbitmq authentication"
    mkdir -p /auth/etc/rabbitmq
    if [ -z "$RABBITMQ_PASSWORD" ]
    then
        RABBITMQ_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
    fi

    echo "${RABBITMQ_PASSWORD}" > /auth/passwords/rabbitmq
fi
