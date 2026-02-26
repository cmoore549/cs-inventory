# Controlled Substance Inventory Management System

**Magnolia Health PLLC**  
**Version 1.0.0**

A comprehensive, DEA-compliant controlled substance inventory management system designed for primary care practices. This web application ensures full compliance with DEA 21 CFR 1304 regulations and North Carolina DHHS requirements.

---

## Features

### Core Inventory Management
- **Real-time Inventory Tracking** - Track all controlled substances with running balances
- **Daily Counts** - Perform and record daily physical counts with dual verification
- **Dispensing** - Record patient dispensing with prescriber tracking
- **Receiving** - Log incoming inventory with supplier and invoice documentation
- **Witnessed Wasting** - Document partial dose wasting with required witness signatures

### Compliance Features
- **Biennial Inventory** - DEA-required inventory every two years with exact Schedule II counts
- **Theft/Loss Reporting** - DEA Form 106 tracking with law enforcement notification
- **Document Storage** - Secure storage for packing slips, invoices, and DEA forms
- **Audit Trail** - Complete transaction logging with timestamps and user identification
- **Registration Tracking** - DEA and NC-DCU registration expiration monitoring

### Reporting
- **Usage Reports** - Analyze controlled substance usage patterns
- **Discrepancy Reports** - Track and resolve inventory discrepancies
- **Audit Logs** - Review all system activity for compliance audits
- **Print-Ready Reports** - Professional reports for DEA inspections

### Security
- **Role-Based Access Control** - Admin, Provider, and Staff permission levels
- **Session Management** - Automatic timeout and secure authentication
- **Password Requirements** - Enforced strong password policies
- **Complete Audit Trail** - IP logging and user tracking for all actions

---

## System Requirements

- **Python** 3.10 or higher
- **Web Server** - Any WSGI-compatible server (Gunicorn, uWSGI)
- **Database** - SQLite (included) or PostgreSQL for production
- **Storage** - Minimum 1GB for application and document storage
- **SSL Certificate** - Required for production deployment

---

## Quick Start

### 1. Clone/Extract the Application
```bash
cd /path/to/cs-inventory
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install flask flask-sqlalchemy werkzeug
```

### 4. Set Environment Variables
```bash
export SECRET_KEY='your-secure-random-key-here'
export FLASK_ENV='production'
```

### 5. Initialize Database
```bash
python app.py  # Creates database and default admin user
```

### 6. Login
- **URL:** http://localhost:5000
- **Username:** admin
- **Password:** changeme123
- ⚠️ **Change this password immediately!**

---

## Production Deployment

### Using Gunicorn (Recommended)

1. **Install Gunicorn**
```bash
pip install gunicorn
```

2. **Create systemd Service** (`/etc/systemd/system/cs-inventory.service`)
```ini
[Unit]
Description=CS Inventory Management System
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/cs-inventory
Environment="SECRET_KEY=your-secure-key"
Environment="FLASK_ENV=production"
ExecStart=/path/to/cs-inventory/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

3. **Start Service**
```bash
sudo systemctl daemon-reload
sudo systemctl enable cs-inventory
sudo systemctl start cs-inventory
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name inventory.your-domain.com;

    ssl_certificate /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;

    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /path/to/cs-inventory/static;
        expires 30d;
    }
}

server {
    listen 80;
    server_name inventory.your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

---

## User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: user management, settings, all transactions |
| **Provider** | Dispense, waste, count, view reports, upload documents |
| **Staff** | Daily counts, receive inventory, view inventory |

---

## DEA Compliance Features

### 21 CFR 1304.11 - Inventory Requirements
- ✅ Biennial inventory (every 2 years)
- ✅ Exact count for Schedule II substances
- ✅ Estimated count allowed for Schedule III-V
- ✅ Separate listing by schedule
- ✅ Date and time of inventory
- ✅ Name/initials of person taking inventory

### 21 CFR 1304.21 - Record Keeping
- ✅ All acquisition records with date, supplier, quantity
- ✅ All distribution/dispensing records
- ✅ Running inventory balance
- ✅ 2-year record retention

### 21 CFR 1301.76 - Storage & Security
- ✅ Access control and audit logging
- ✅ Document storage for security records

### DEA Form 106 - Theft/Loss
- ✅ Incident documentation within 1 business day
- ✅ Law enforcement notification tracking
- ✅ DEA submission status monitoring

---

## NC DHHS Requirements

- ✅ Annual registration renewal tracking
- ✅ 60-day expiration warnings
- ✅ NC-DCU registration monitoring
- ✅ Prescriber DEA number verification

---

## File Structure

```
cs-inventory/
├── app.py                 # Main Flask application
├── README.md              # This documentation
├── requirements.txt       # Python dependencies
├── instance/              # SQLite database (auto-created)
├── static/
│   ├── css/
│   │   └── style.css      # Application styles
│   ├── js/                # JavaScript files
│   └── uploads/           # Document storage
├── templates/             # HTML templates
│   ├── base.html          # Base layout
│   ├── dashboard.html     # Main dashboard
│   ├── inventory.html     # Inventory list
│   ├── daily_count.html   # Daily counting
│   ├── dispense.html      # Dispensing form
│   ├── waste.html         # Wasting form
│   ├── receive_inventory.html
│   ├── biennial_inventory.html
│   ├── reports.html
│   └── ...                # Additional templates
└── venv/                  # Virtual environment
```

---

## Database Backup

### SQLite Backup
```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/backups/cs-inventory"
DATE=$(date +%Y%m%d_%H%M%S)
cp /path/to/cs-inventory/instance/cs_inventory.db "$BACKUP_DIR/backup_$DATE.db"
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
```

### PostgreSQL Migration (Recommended for Production)
```python
# In app.py, change:
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@localhost/cs_inventory'
```

---

## Security Recommendations

1. **Change Default Password** - Immediately after first login
2. **Use HTTPS** - Required for production; never transmit data over HTTP
3. **Strong SECRET_KEY** - Generate with `python -c "import secrets; print(secrets.token_hex(32))"`
4. **Regular Backups** - Daily automated backups with off-site storage
5. **Access Logging** - Monitor audit logs for suspicious activity
6. **Update Dependencies** - Regular security updates
7. **Firewall** - Restrict access to necessary ports only
8. **Session Timeout** - Default 30 minutes; adjust in settings

---

## Troubleshooting

### Application Won't Start
```bash
# Check logs
journalctl -u cs-inventory -f

# Verify permissions
chmod 755 /path/to/cs-inventory
chown -R www-data:www-data /path/to/cs-inventory
```

### Database Errors
```bash
# Reset database (CAUTION: deletes all data)
rm instance/cs_inventory.db
python app.py
```

### Document Upload Fails
```bash
# Check upload directory permissions
chmod 755 static/uploads
chown www-data:www-data static/uploads
```

---

## Support

For questions about this system, contact:
- **Developer:** Claude AI Assistant
- **Practice:** Magnolia Health PLLC
- **Location:** Forest City, North Carolina

For DEA compliance questions:
- **DEA Diversion Control Division:** 1-800-882-9539
- **NC DHHS:** https://www.ncdhhs.gov

---

## License

Proprietary software developed for Magnolia Health PLLC. Not for distribution.

---

## Changelog

### Version 1.0.0 (January 2026)
- Initial production release
- Full DEA 21 CFR 1304 compliance
- NC DHHS registration tracking
- Biennial inventory workflow
- Daily count with dual verification
- Dispensing and wasting with witness requirements
- Theft/loss reporting (DEA Form 106)
- Document management system
- Comprehensive audit logging
- Role-based access control
- Print-ready compliance reports
