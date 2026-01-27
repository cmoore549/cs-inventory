# Deploying CS Inventory to Digital Ocean

Complete step-by-step guide to deploy the Controlled Substance Inventory System to a Digital Ocean droplet with SSL.

---

## Table of Contents
1. [Create Digital Ocean Droplet](#1-create-digital-ocean-droplet)
2. [Initial Server Setup](#2-initial-server-setup)
3. [Install Dependencies](#3-install-dependencies)
4. [Deploy Application](#4-deploy-application)
5. [Configure Gunicorn](#5-configure-gunicorn)
6. [Configure Nginx](#6-configure-nginx)
7. [Set Up SSL with Let's Encrypt](#7-set-up-ssl-with-lets-encrypt)
8. [Configure Systemd Service](#8-configure-systemd-service)
9. [Set Up Automated Backups](#9-set-up-automated-backups)
10. [Post-Deployment Checklist](#10-post-deployment-checklist)

---

## 1. Create Digital Ocean Droplet

### Step 1.1: Log into Digital Ocean
Go to [cloud.digitalocean.com](https://cloud.digitalocean.com) and log in.

### Step 1.2: Create a New Droplet
1. Click **Create** → **Droplets**
2. Choose the following settings:

| Setting | Recommended Value |
|---------|------------------|
| **Region** | Choose closest to your location (e.g., New York) |
| **Image** | Ubuntu 24.04 (LTS) x64 |
| **Size** | Basic → Regular → $6/mo (1 GB RAM, 1 CPU, 25 GB SSD) |
| **Authentication** | SSH Key (recommended) or Password |

### Step 1.3: Add SSH Key (Recommended)
If you don't have an SSH key:
```bash
# On your LOCAL computer, run:
ssh-keygen -t ed25519 -C "your_email@example.com"

# View your public key:
cat ~/.ssh/id_ed25519.pub
```
Copy the output and paste it into Digital Ocean's SSH key field.

### Step 1.4: Finalize
1. Set hostname: `cs-inventory` (or your preferred name)
2. Click **Create Droplet**
3. Note your droplet's IP address (e.g., `123.45.67.89`)

---

## 2. Initial Server Setup

### Step 2.1: Connect to Your Droplet
```bash
ssh root@YOUR_DROPLET_IP
```

### Step 2.2: Update System
```bash
apt update && apt upgrade -y
```

### Step 2.3: Create Application User
```bash
# Create user for running the application
adduser --system --group --home /opt/cs-inventory csapp

# Create directory structure
mkdir -p /opt/cs-inventory
chown csapp:csapp /opt/cs-inventory
```

### Step 2.4: Configure Firewall
```bash
# Enable UFW firewall
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw enable

# Verify status
ufw status
```

### Step 2.5: Set Timezone
```bash
timedatectl set-timezone America/New_York
```

---

## 3. Install Dependencies

### Step 3.1: Install Python and Required Packages
```bash
apt install -y python3 python3-pip python3-venv nginx supervisor
```

### Step 3.2: Install Certbot for SSL
```bash
apt install -y certbot python3-certbot-nginx
```

---

## 4. Deploy Application

### Step 4.1: Upload Application Files

**Option A: Using SCP (from your local machine)**
```bash
# On your LOCAL machine, run:
scp cs-inventory-v1.1.0.zip root@YOUR_DROPLET_IP:/opt/cs-inventory/
```

**Option B: Using Git (if you have a repository)**
```bash
# On the server:
cd /opt/cs-inventory
git clone https://github.com/yourusername/cs-inventory.git .
```

**Option C: Using wget (if hosted somewhere)**
```bash
cd /opt/cs-inventory
wget YOUR_FILE_URL -O cs-inventory.zip
```

### Step 4.2: Extract and Set Up
```bash
cd /opt/cs-inventory

# If using zip file:
apt install -y unzip
unzip cs-inventory-v1.1.0.zip
mv cs-inventory/* .
rm -rf cs-inventory cs-inventory-v1.1.0.zip

# Set ownership
chown -R csapp:csapp /opt/cs-inventory
```

### Step 4.3: Create Virtual Environment
```bash
cd /opt/cs-inventory

# Create venv as csapp user
sudo -u csapp python3 -m venv venv

# Activate and install dependencies
sudo -u csapp /opt/cs-inventory/venv/bin/pip install --upgrade pip
sudo -u csapp /opt/cs-inventory/venv/bin/pip install -r requirements.txt
sudo -u csapp /opt/cs-inventory/venv/bin/pip install gunicorn
```

### Step 4.4: Create Required Directories
```bash
mkdir -p /opt/cs-inventory/instance
mkdir -p /opt/cs-inventory/static/uploads/logo
chown -R csapp:csapp /opt/cs-inventory/instance
chown -R csapp:csapp /opt/cs-inventory/static/uploads
```

### Step 4.5: Set Environment Variables
```bash
# Generate a secure secret key
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Create environment file
cat > /opt/cs-inventory/.env << EOF
SECRET_KEY=${SECRET_KEY}
FLASK_ENV=production
EOF

chown csapp:csapp /opt/cs-inventory/.env
chmod 600 /opt/cs-inventory/.env
```

### Step 4.6: Initialize Database
```bash
cd /opt/cs-inventory
sudo -u csapp /opt/cs-inventory/venv/bin/python -c "
from app import app, db, init_db
with app.app_context():
    db.create_all()
    init_db()
print('Database initialized!')
"
```

---

## 5. Configure Gunicorn

### Step 5.1: Test Gunicorn
```bash
cd /opt/cs-inventory
sudo -u csapp /opt/cs-inventory/venv/bin/gunicorn --bind 127.0.0.1:8000 app:app

# Press Ctrl+C to stop after confirming it works
```

### Step 5.2: Create Gunicorn Config
```bash
cat > /opt/cs-inventory/gunicorn.conf.py << 'EOF'
# Gunicorn configuration file
import multiprocessing

# Bind to localhost only (Nginx will proxy)
bind = "127.0.0.1:8000"

# Workers
workers = 2
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging
accesslog = "/var/log/cs-inventory/access.log"
errorlog = "/var/log/cs-inventory/error.log"
loglevel = "info"

# Process naming
proc_name = "cs-inventory"

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
EOF

chown csapp:csapp /opt/cs-inventory/gunicorn.conf.py
```

### Step 5.3: Create Log Directory
```bash
mkdir -p /var/log/cs-inventory
chown csapp:csapp /var/log/cs-inventory
```

---

## 6. Configure Nginx

### Step 6.1: Create Nginx Configuration
Replace `yourdomain.com` with your actual domain (or use the IP address temporarily).

```bash
cat > /etc/nginx/sites-available/cs-inventory << 'EOF'
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Max upload size (for document uploads)
    client_max_body_size 16M;

    # Static files
    location /static {
        alias /opt/cs-inventory/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Proxy to Gunicorn
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 300s;
        proxy_read_timeout 300s;
    }
}
EOF
```

### Step 6.2: Enable the Site
```bash
# Remove default site
rm -f /etc/nginx/sites-enabled/default

# Enable cs-inventory site
ln -sf /etc/nginx/sites-available/cs-inventory /etc/nginx/sites-enabled/

# Test configuration
nginx -t

# Reload Nginx
systemctl reload nginx
```

---

## 7. Set Up SSL with Let's Encrypt

> **Note:** You must have a domain name pointed to your droplet's IP address for this step.

### Step 7.1: Point Your Domain to the Droplet
In your domain registrar's DNS settings:
- Add an **A record** pointing `yourdomain.com` to your droplet IP
- Add an **A record** pointing `www.yourdomain.com` to your droplet IP
- Wait 5-10 minutes for DNS propagation

### Step 7.2: Obtain SSL Certificate
```bash
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

Follow the prompts:
- Enter your email address
- Agree to terms of service
- Choose whether to redirect HTTP to HTTPS (recommended: Yes)

### Step 7.3: Verify Auto-Renewal
```bash
certbot renew --dry-run
```

---

## 8. Configure Systemd Service

### Step 8.1: Create Service File
```bash
cat > /etc/systemd/system/cs-inventory.service << 'EOF'
[Unit]
Description=Controlled Substance Inventory System
After=network.target

[Service]
Type=notify
User=csapp
Group=csapp
RuntimeDirectory=gunicorn
WorkingDirectory=/opt/cs-inventory
Environment="PATH=/opt/cs-inventory/venv/bin"
EnvironmentFile=/opt/cs-inventory/.env
ExecStart=/opt/cs-inventory/venv/bin/gunicorn --config gunicorn.conf.py app:app
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=10
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
```

### Step 8.2: Enable and Start Service
```bash
# Reload systemd
systemctl daemon-reload

# Enable service to start on boot
systemctl enable cs-inventory

# Start the service
systemctl start cs-inventory

# Check status
systemctl status cs-inventory
```

### Step 8.3: Useful Commands
```bash
# View logs
journalctl -u cs-inventory -f

# Restart service
systemctl restart cs-inventory

# Stop service
systemctl stop cs-inventory
```

---

## 9. Set Up Automated Backups

### Step 9.1: Create Backup Script
```bash
cat > /opt/cs-inventory/backup.sh << 'EOF'
#!/bin/bash

# Backup configuration
BACKUP_DIR="/opt/cs-inventory/backups"
DB_PATH="/opt/cs-inventory/instance/controlled_substances.db"
UPLOADS_DIR="/opt/cs-inventory/static/uploads"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Backup database
if [ -f "$DB_PATH" ]; then
    cp "$DB_PATH" "$BACKUP_DIR/db_backup_$TIMESTAMP.db"
    gzip "$BACKUP_DIR/db_backup_$TIMESTAMP.db"
    echo "Database backed up: db_backup_$TIMESTAMP.db.gz"
fi

# Backup uploads
if [ -d "$UPLOADS_DIR" ]; then
    tar -czf "$BACKUP_DIR/uploads_backup_$TIMESTAMP.tar.gz" -C "$UPLOADS_DIR" .
    echo "Uploads backed up: uploads_backup_$TIMESTAMP.tar.gz"
fi

# Remove old backups
find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete
echo "Cleaned up backups older than $RETENTION_DAYS days"

echo "Backup completed at $(date)"
EOF

chmod +x /opt/cs-inventory/backup.sh
chown csapp:csapp /opt/cs-inventory/backup.sh
```

### Step 9.2: Schedule Daily Backups
```bash
# Add cron job for daily backups at 2 AM
(crontab -l 2>/dev/null; echo "0 2 * * * /opt/cs-inventory/backup.sh >> /var/log/cs-inventory/backup.log 2>&1") | crontab -
```

### Step 9.3: (Optional) Off-Site Backups
For critical data, consider copying backups to Digital Ocean Spaces or another location:
```bash
# Install s3cmd for DO Spaces
apt install -y s3cmd

# Configure (you'll need DO Spaces credentials)
s3cmd --configure
```

---

## 10. Post-Deployment Checklist

### Immediate Actions

- [ ] **Change default admin password**
  - Log in with `admin` / `changeme123`
  - Go to Settings → Edit your user → Change password

- [ ] **Add DEA Registration**
  - Settings → Add Registration
  - Enter your DEA number and expiration date

- [ ] **Add NC-DCU Registration**
  - Settings → Add Registration
  - Enter your NC Drug Control registration

- [ ] **Configure Practice Information**
  - Settings → Practice Information
  - Add practice name, address, phone, fax

- [ ] **Upload Practice Logo** (optional)
  - Settings → Upload Logo

- [ ] **Add Staff Users**
  - Settings → Add User
  - Create accounts for each staff member

### Security Verification

- [ ] Verify HTTPS is working: `https://yourdomain.com`
- [ ] Verify HTTP redirects to HTTPS
- [ ] Test login functionality
- [ ] Verify file uploads work
- [ ] Check that backups are running

### Test Core Functions

- [ ] Add a test medication
- [ ] Receive inventory
- [ ] Perform a daily count
- [ ] Record a dispensing transaction
- [ ] Record a waste transaction with witness

---

## Troubleshooting

### Application Won't Start
```bash
# Check service status
systemctl status cs-inventory

# View detailed logs
journalctl -u cs-inventory -n 50

# Check Gunicorn error log
tail -f /var/log/cs-inventory/error.log
```

### 502 Bad Gateway
```bash
# Ensure Gunicorn is running
systemctl status cs-inventory

# Check if port 8000 is listening
ss -tlnp | grep 8000

# Restart services
systemctl restart cs-inventory
systemctl restart nginx
```

### Permission Errors
```bash
# Fix ownership
chown -R csapp:csapp /opt/cs-inventory

# Fix upload directory permissions
chmod 755 /opt/cs-inventory/static/uploads
```

### Database Errors
```bash
# Ensure database directory exists
mkdir -p /opt/cs-inventory/instance
chown csapp:csapp /opt/cs-inventory/instance

# Reinitialize database (WARNING: loses data)
sudo -u csapp /opt/cs-inventory/venv/bin/python -c "
from app import app, db, init_db
with app.app_context():
    db.create_all()
    init_db()
"
```

### SSL Certificate Issues
```bash
# Check certificate status
certbot certificates

# Force renewal
certbot renew --force-renewal

# Check Nginx config
nginx -t
```

---

## Updating the Application

### Step 1: Backup First
```bash
/opt/cs-inventory/backup.sh
```

### Step 2: Upload New Files
```bash
# Upload new zip file
scp cs-inventory-v1.2.0.zip root@YOUR_DROPLET_IP:/tmp/

# On server:
cd /opt/cs-inventory
systemctl stop cs-inventory
unzip -o /tmp/cs-inventory-v1.2.0.zip -d /tmp/
cp -r /tmp/cs-inventory/* /opt/cs-inventory/
chown -R csapp:csapp /opt/cs-inventory
```

### Step 3: Update Dependencies
```bash
sudo -u csapp /opt/cs-inventory/venv/bin/pip install -r requirements.txt
```

### Step 4: Restart
```bash
systemctl start cs-inventory
systemctl status cs-inventory
```

---

## Support

For issues with this deployment guide, check:
- Digital Ocean Community: https://www.digitalocean.com/community
- Flask Documentation: https://flask.palletsprojects.com
- Nginx Documentation: https://nginx.org/en/docs/

---

*Last Updated: January 2026*
