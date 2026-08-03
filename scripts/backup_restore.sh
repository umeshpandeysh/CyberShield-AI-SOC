#!/usr/bin/env bash
# CyberShield-AI-SOC Database Backup & Restore Automation Script

set -e

DB_CONTAINER="cybershield-postgres"
DB_USER="postgres"
DB_NAME="cybershield_db"
BACKUP_DIR="./backups"

mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

if [ "$1" == "backup" ]; then
    echo "Creating PostgreSQL backup for $DB_NAME..."
    BACKUP_FILE="$BACKUP_DIR/cybershield_backup_$TIMESTAMP.sql.gz"
    docker exec -t $DB_CONTAINER pg_dump -U $DB_USER $DB_NAME | gzip > "$BACKUP_FILE"
    echo "Backup completed successfully: $BACKUP_FILE"

elif [ "$1" == "restore" ]; then
    if [ -z "$2" ]; then
        echo "Usage: ./backup_restore.sh restore <path_to_backup.sql.gz>"
        exit 1
    fi
    RESTORE_FILE="$2"
    echo "Restoring PostgreSQL database from $RESTORE_FILE..."
    gunzip -c "$RESTORE_FILE" | docker exec -i $DB_CONTAINER psql -U $DB_USER -d $DB_NAME
    echo "Database restoration completed successfully!"

else
    echo "CyberShield-AI-SOC Backup & Restore Tool"
    echo "Usage:"
    echo "  ./scripts/backup_restore.sh backup"
    echo "  ./scripts/backup_restore.sh restore <backup_file.sql.gz>"
fi
