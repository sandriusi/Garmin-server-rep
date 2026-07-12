# FitMind — Garmin sync service (deploy guide)

This is a small **second** service (separate from your Node AI server) whose only
job is signing into Garmin Connect — including accounts with **two-factor (MFA)**,
which the Node library couldn't do. It's written in Python.

You deploy it once on Render as a new service. ~10 minutes.

## Before you start
- You already have the Supabase project and the Node AI server running.
- Run `setup-garmin.sql` in Supabase (SQL Editor) if you haven't — it creates the
  encrypted `garmin_tokens` table.

## Step 1 — Create the Render service
1. Push this `garmin-service/` folder to a GitHub repo (its own repo, or a
   subfolder of an existing one).
2. Render → **New +** → **Web Service** → connect that repo.
3. Settings:
   - **Root Directory**: `garmin-service` (if it's a subfolder; otherwise leave blank)
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python app.py`
   - **Instance type**: Free is fine.
   - **Important — Scaling**: keep it at **1 instance** and don't switch the start
     command to gunicorn with multiple workers. The MFA step hands the 6-digit
     code between two requests in memory, so it must be one single process.

## Step 2 — Environment variables
Render → the new service → **Environment**, add these three (reuse the SAME values
you gave the Node server where they overlap):

| Variable | Value |
|---|---|
| `SUPABASE_URL` | your project URL, e.g. `https://abcdefgh.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase → Settings → API keys → the **secret / service_role** key |
| `GARMIN_ENC_KEY` | any long random string you invent (encrypts stored Garmin tokens) |

Save → Render builds and deploys. When it's live, open its URL — `…/healthz`
should show `{"ok": true, "service": "fitmind-garmin", "configured": true}`.

## Step 3 — Point the app at it
In the app's `js/config.js`, set the Garmin service URL to the new service's
address, then re-upload `config.js` (or the whole app):

```js
window.FITMIND_GARMIN_URL = 'https://fitmind-garmin.onrender.com';
```

That's it. In the app: **Profile → Connections → Garmin → Connect**. Enter your
Garmin email + password; when Garmin asks, a **6-digit code** field appears
(check your email or the Garmin Connect app). After that it syncs Body Battery,
sleep stages, HRV, training status, VO2 max and activity detail.

## Notes & limitations
- **Free-tier sleep**: the service sleeps after ~15 min idle and takes ~30–60 s to
  wake on the next connect/sync. Your first tap after a while may be slow — that's
  the wake-up, not a failure.
- **Unofficial**: Garmin has no official API for individuals. This uses the
  community `garminconnect` library, so a Garmin-side change can occasionally
  break sync until the library updates. Your FitMind data and the rest of the app
  are unaffected if that happens — Garmin simply shows "reconnect".
- **Password**: only ever transits to this service over HTTPS, is never logged or
  stored; only encrypted tokens are kept. Disconnect deletes them.
