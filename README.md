# LedgerX — Debit & Credit Tracker

A fully self-contained finance tracking app deployable on Render via Docker.

## Stack
- Node.js + Express (backend API)
- SQLite via better-sqlite3 (zero external DB needed)
- JWT + bcrypt (auth)
- Vanilla HTML/CSS/JS (frontend, no build step)

## Deploy on Render

1. Push this folder to a GitHub repo
2. On Render: New → Web Service → Docker environment
3. Add a **Disk** at mount path `/app/data` (1 GB, for SQLite persistence)
4. Set env vars: `JWT_SECRET=your_long_secret_here` and `PORT=3000`
5. Deploy!

## Run Locally

```bash
npm install
node server.js
# Open http://localhost:3000
```
