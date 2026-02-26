# Deploy to Railway (5 minutes)

## Option A: Deploy via GitHub (Recommended)

### Step 1: Push to GitHub
```bash
# Extract the zip first, then:
cd cs-inventory
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/cs-inventory.git
git push -u origin main
```

### Step 2: Connect Railway to GitHub
1. Go to [railway.app](https://railway.app) → **New Project**
2. Click **Deploy from GitHub repo**
3. Select your `cs-inventory` repository
4. Railway auto-detects Python and starts deploying

### Step 3: Add Environment Variable
1. Click your project → **Variables**
2. Add:
   ```
   SECRET_KEY = (click "Generate" or paste a random 64-character string)
   ```

### Step 4: Get Your URL
1. Go to **Settings** → **Networking**
2. Click **Generate Domain**
3. Your app is live at `https://cs-inventory-xxxx.up.railway.app`

---

## Option B: Deploy via Railway CLI

### Step 1: Install Railway CLI
```bash
# Mac
brew install railway

# Windows
npm install -g @railway/cli

# Linux
curl -fsSL https://railway.app/install.sh | sh
```

### Step 2: Login & Deploy
```bash
cd cs-inventory
railway login
railway init
railway up
```

### Step 3: Add Environment Variable
```bash
railway variables set SECRET_KEY=$(openssl rand -hex 32)
```

### Step 4: Get Your URL
```bash
railway domain
```

---

## Post-Deploy Setup

1. **Visit your Railway URL**
2. **Login**: `admin` / `changeme123`
3. **IMMEDIATELY change the admin password** in Settings → Edit User
4. Add your DEA and NC registrations
5. Add staff users

---

## Important Notes

### Database Persistence
Railway's free tier uses ephemeral storage. Your SQLite database will reset on redeploys. For production:

**Option 1: Upgrade to Railway Pro ($5/mo)** - includes persistent volumes

**Option 2: Use Railway PostgreSQL**
1. In Railway, click **New** → **Database** → **PostgreSQL**
2. Copy the `DATABASE_URL` from the PostgreSQL service
3. Add it as a variable to your web service
4. (Requires code changes to use PostgreSQL instead of SQLite)

### File Uploads
Same issue - uploads won't persist on free tier. For production, use:
- Railway Pro with volumes
- Cloudinary for images
- AWS S3 for documents

---

## Costs

| Plan | Price | Storage | Notes |
|------|-------|---------|-------|
| Free Trial | $0 | Ephemeral | 500 hours/month, resets on deploy |
| Hobby | $5/mo | Ephemeral | Unlimited hours |
| Pro | $20/mo | Persistent volumes | Production ready |

---

## Troubleshooting

### Build Failed
Check the build logs in Railway dashboard. Common issues:
- Missing `requirements.txt`
- Python version mismatch

### App Crashes
```bash
railway logs
```

### Database Errors
The SQLite database is created in `/app/instance/`. If it's not persisting:
```bash
railway variables set SQLALCHEMY_DATABASE_URI=sqlite:///controlled_substances.db
```

---

## Quick Reference

```bash
# Deploy changes
git add . && git commit -m "Update" && git push

# View logs
railway logs

# Open app
railway open

# SSH into container
railway shell

# Set environment variable
railway variables set KEY=value
```
