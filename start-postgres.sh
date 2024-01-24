#!/bin/bash


docker stop domain-postgres > /dev/null 2>&1
docker rm domain-postgres > /dev/null 2>&1

docker run --name domain-postgres -d -p 5432:5432 \
  -e POSTGRES_PASSWORD="ChangeDefaultPassword!" \
  -e POSTGRES_HOST_AUTH_METHOD="scram-sha-256" \
  -e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256 --auth-local=scram-sha-256" \
  -v "$(pwd)/pg-initdb:/docker-entrypoint-initdb.d:ro" \
  postgres:14
