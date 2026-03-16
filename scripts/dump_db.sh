#!/bin/bash

# Load environment variables from .env file
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

DB_PATH=$(echo $DATABASE_URL | sed 's/sqlite:\/\///')
mkdir -p docs/db
sqlite3 "$DB_PATH" .schema > docs/db/db_schema.sql
