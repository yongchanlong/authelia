#!/bin/bash

set -e

docker-compose \
  -f docker-compose.dockerhub.yml \
  -f example/docker-compose.base.yml \
  -f example/mongo/docker-compose.yml \
  -f example/redis/docker-compose.yml \
  -f example/nginx/authelia/docker-compose.yml \
  -f example/nginx/backend/docker-compose.yml \
  -f example/nginx/portal/docker-compose.yml \
  -f example/smtp/docker-compose.yml \
  -f example/httpbin/docker-compose.yml \
  -f example/ldap/docker-compose.yml $*
