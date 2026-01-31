#!/bin/bash
# Database Backup Script
# Controlled Substance Inventory Management System
# Magnolia Health PLLC
#
# Add to crontab for daily backups:
# 0 2 * * * /path/to/cs-inventory/backup.sh

# Configuration
APP_DIR="/path/to/cs-inventory"
BACKUP_DIR="/path/to/backups/cs-inventory"
DB_FILE="$APP_DIR/instance/cs_inventory.db"
UPLOADS_DIR="$APP_DIR/static/uploads"
RETENTION_DAYS=30

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE=$(date +%Y-%m-%d)

echo "=========================================="
echo "CS Inventory Backup - $DATE"
echo "=========================================="

# Check if database exists
if [ ! -f "$DB_FILE" ]; then
    echo -e "${RED}ERROR: Database file not found at $DB_FILE${NC}"
    exit 1
fi

# Backup database
echo -n "Backing up database... "
cp "$DB_FILE" "$BACKUP_DIR/database_$TIMESTAMP.db"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    exit 1
fi

# Backup uploads (documents)
if [ -d "$UPLOADS_DIR" ]; then
    echo -n "Backing up documents... "
    tar -czf "$BACKUP_DIR/uploads_$TIMESTAMP.tar.gz" -C "$APP_DIR/static" uploads
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi
fi

# Create combined backup archive
echo -n "Creating combined archive... "
tar -czf "$BACKUP_DIR/full_backup_$TIMESTAMP.tar.gz" \
    "$BACKUP_DIR/database_$TIMESTAMP.db" \
    "$BACKUP_DIR/uploads_$TIMESTAMP.tar.gz" 2>/dev/null
rm -f "$BACKUP_DIR/database_$TIMESTAMP.db" "$BACKUP_DIR/uploads_$TIMESTAMP.tar.gz"
echo -e "${GREEN}OK${NC}"

# Calculate backup size
BACKUP_SIZE=$(du -h "$BACKUP_DIR/full_backup_$TIMESTAMP.tar.gz" | cut -f1)
echo "Backup size: $BACKUP_SIZE"

# Clean up old backups
echo -n "Cleaning up backups older than $RETENTION_DAYS days... "
DELETED=$(find "$BACKUP_DIR" -name "full_backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete -print | wc -l)
echo -e "${GREEN}OK${NC} ($DELETED files removed)"

# List recent backups
echo ""
echo "Recent backups:"
ls -lh "$BACKUP_DIR"/*.tar.gz 2>/dev/null | tail -5

echo ""
echo "=========================================="
echo -e "${GREEN}Backup complete!${NC}"
echo "=========================================="
echo "File: $BACKUP_DIR/full_backup_$TIMESTAMP.tar.gz"
echo ""

# Optional: Copy to remote location
# scp "$BACKUP_DIR/full_backup_$TIMESTAMP.tar.gz" user@backup-server:/backups/
