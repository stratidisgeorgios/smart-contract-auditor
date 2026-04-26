# Deployment Guide

This guide explains how to deploy the Smart Contract Auditor: both the backend (Render) and the frontend (Vercel). Read it once before your first deploy, it's simpler than it looks.

---

## Shared project accounts

All deployments are managed through a shared Gmail project account. Use these credentials to access Render, Vercel and Docker Hub:

```
Email:  smart.contract.auditor.project@gmail.com
Password: (shared internally with the team)
```

> For safety, don't commit passwords or API keys to the repository.

## The deployment process 

GitLab UZH  →  source code (commits from team)
     ↓
  your computer  →  docker build + docker push
     ↓
Docker Hub  →  stores created image
     ↓
Render      →  downloads image → backend live
     ↓
Vercel      →  frontend → calls backend


## Overview: when should you deploy?

There are two types of deploy:

**Preview** -> for work in progress. When you're working on a branch and want to share a live version with teammates to review before merging, or to see the changes yourself. Only deploys the frontend.

**Production** —> for finished, reviewed work. Only deploy to production once your changes have been merged into `main`. Both frontend and backend should be deployed from `main`.

```
Feature branch  →  Preview deploy (frontend only, for review)
      ↓
   merge to main
      ↓
Production deploy (frontend + backend if backend changed)
```


## First steps (first time only)

Install the Vercel CLI on your machine:

```bash
npm install -g vercel
```

Then log in with the project account:

```bash
vercel login
# Choose "Continue with Email"
# Enter: smart.contract.auditor.project@gmail.com
# Click the verification link sent to that email
# If Vercel asks you which project, probably it will default the correct one, which is: smartcontractauditorproject-1459s-projects . Not sure if you'll have to do this step tho
```

For backend deploys you also need Docker installed: https://www.docker.com/get-started

Then log in to Docker Hub:

```bash
docker login
# Username: smartcontractauditor
# Password: (shared internally)
```

You only need to do all of this once per machine.

---

## Frontend deploys (Vercel)

The frontend lives at:
```
https://smart-contract-auditor-fawn.vercel.app
```

### Preview deploy —> while working on a branch

Use this when you want to share your in-progress changes with teammates without touching production or you want to test your frontend changes. Run this from your feature branch:

```bash
# Make sure you're on your feature branch
git checkout your-feature-branch

cd frontend/
vercel
```

Vercel will give you a unique preview URL like:
```
https://smart-contract-auditor-abc123.vercel.app
```

Share that URL with your team for review (if you want) or see the changes you made in your branch from there. It won't affect the production URL.

### Production deploy —> after merging to main

Only do this once your changes are in `main`:

```bash
# Make sure you're on main and it's up to date
git checkout main
git pull origin main

cd frontend/
vercel --prod
```

The production URL stays the same after every deploy:
```
https://smart-contract-auditor-fawn.vercel.app
```

## Backend deploys (Render via Docker Hub)

The backend lives at:
```
https://blockchain-seminar-smart-contract-auditor.onrender.com
```

The backend has no preview environment —> there is only production. This means you can manually deploy from your feature branch to test changes, but if something breaks, then you have to go to main and deploy manually from there to restore the working app (as main should be free from breaking bugs).
So if you deploy from your branch and something goes wrong (which is totally normal), then restore production before disconnecting —> just switch to `main` and redeploy (steps below). However if your changes in your branch work, then you can merge your branch to main and then again redeploy. The idea is that after each "implementation session" we redeploy main if we deployed something in our branches to test.

### Step 1 —> Build and push the Docker image

Run this from whichever branch you're on (`main` or your feature branch):

```bash
cd backend/
docker build -t smartcontractauditor/smart-contract-auditor-backend:latest .
docker push smartcontractauditor/smart-contract-auditor-backend:latest
```

This uploads the new image to Docker Hub. It usually takes 2–5 minutes.

### Step 2 — Trigger the deploy on Render

1. Go to https://render.com and log in with the project email
2. Click on the service **blockchain-seminar-smart-contract-auditor**
3. Click **Manual Deploy → Deploy latest image** (top right)
4. Wait for the deploy to finish — you'll see the logs in real time

### Step 3 — Verify it's working

Open this URL in your browser:
```
https://blockchain-seminar-smart-contract-auditor.onrender.com/api/v1/health
```

You should see `{"status":"ok"}`.

---

## Typical workflow for a new feature

```
1. Create a feature branch
   git checkout -b feat/my-feature

2. Make your changes and commit
   git add .
   git commit -m "feat: my feature description"
   git push origin feat/my-feature

3. Frontend: Preview deploy (you can share with team for review)
   cd frontend/
   vercel
   → copy the preview URL and share it with team

4. Once approved, open a Merge Request on GitLab and merge to main

5. Pull main 
   git checkout main
   git pull origin main

6. Production deploy for frontend
   cd frontend/
   vercel --prod

7. Production deploy for backend (only if backend files changed) (do this from your branch if you are implementing changes)
   cd backend/
   docker build -t smartcontractauditor/smart-contract-auditor-backend:latest .
   docker push smartcontractauditor/smart-contract-auditor-backend:latest
   → then go to Render dashboard → Manual Deploy → Deploy latest image
```

---

## Quick reference

| What | Command | When |
|---|---|---|
| Frontend preview | `cd frontend && vercel` | On a feature branch, for review |
| Frontend production | `cd frontend && vercel --prod` | After merge to main |
| Backend production | `docker build` + `docker push` + Manual Deploy on Render | On a feature branch if working on it, or on main if everything works ok (only if backend changed) |
| Check backend health | open `.../api/v1/health` in browser | After any backend deploy to see that backend is up|

---

## Troubleshooting

**Docker build fails**

Make sure Docker Desktop is running on your machine before running `docker build`.