#!/bin/bash
# Controlled Substance Inventory Management System
# Deployment Setup Script
# Magnolia Health PLLC

set -e

echo "=========================================="
echo "CS Inventory Management System Setup"
echo "Magnolia Health PLLC"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo -n "Checking Python version... "
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 10 ]; then
    echo -e "${GREEN}OK${NC} (Python $PYTHON_VERSION)"
else
    echo -e "${RED}FAILED${NC}"
    echo "Python 3.10 or higher required. Found: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -n "Creating virtual environment... "
    python3 -m venv venv
    echo -e "${GREEN}OK${NC}"
else
    echo -e "Virtual environment already exists... ${YELLOW}SKIPPED${NC}"
fi

# Activate virtual environment
echo -n "Activating virtual environment... "
source venv/bin/activate
echo -e "${GREEN}OK${NC}"

# Install/upgrade pip
echo -n "Upgrading pip... "
pip install --upgrade pip -q
echo -e "${GREEN}OK${NC}"

# Install requirements
echo -n "Installing dependencies... "
pip install -r requirements.txt -q
echo -e "${GREEN}OK${NC}"

# Create necessary directories
echo -n "Creating directories... "
mkdir -p static/uploads
mkdir -p instance
chmod 755 static/uploads
chmod 755 instance
echo -e "${GREEN}OK${NC}"

# Generate SECRET_KEY if not set
if [ -z "$SECRET_KEY" ]; then
    echo ""
    echo -e "${YELLOW}WARNING: SECRET_KEY not set!${NC}"
    echo ""
    NEW_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "Generated SECRET_KEY for you:"
    echo ""
    echo "  export SECRET_KEY='$NEW_KEY'"
    echo ""
    echo "Add this to your shell profile or systemd service file."
    echo ""
fi

# Test application
echo -n "Testing application... "
python3 -c "from app import app, db" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "Application import failed. Check for errors."
    exit 1
fi

echo ""
echo "=========================================="
echo -e "${GREEN}Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Set your SECRET_KEY environment variable"
echo "   export SECRET_KEY='your-generated-key'"
echo ""
echo "2. Start the development server:"
echo "   python app.py"
echo ""
echo "3. Access the application:"
echo "   http://localhost:5000"
echo ""
echo "4. Login with default credentials:"
echo "   Username: admin"
echo "   Password: changeme123"
echo ""
echo -e "${RED}⚠️  IMPORTANT: Change the default password immediately!${NC}"
echo ""
echo "For production deployment:"
echo "  gunicorn -w 4 -b 0.0.0.0:8000 app:app"
echo ""
echo "See README.md for full deployment instructions."
echo ""
