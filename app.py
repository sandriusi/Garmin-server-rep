"""
FitMind V2 — Garmin Connect sync microservice
================================================================================
A small, separate service (from the Node AI server) that handles the ONE thing
Node can't: logging into Garmin Connect for accounts that use two-factor (MFA).

It uses the `garminconnect` Python library, which supports MFA via a blocking
`prompt_mfa` callback. To make that work across two web requests (submit
credentials, then submit the 6-digit code), each pending login runs in a
background thread that blocks on the callback until /api/garmin/mfa delivers the
code. Pending logins live in memory keyed by user, with a 5-minute TTL.

Security:
  - The Garmin email/password reach this service ONCE, over HTTPS, and are never
    logged or persisted. Only the resulting OAuth tokens are kept.
  - Tokens are AES-256-GCM encrypted at rest in the Supabase `garmin_tokens`
    table (service-role access only — see setup-garmin.sql).
  - Every request must carry the signed-in FitMind user's Supabase token, which
    we verify against the project's public keys (ES256).

Deploy: a single-instance, single-process service (the in-memory MFA hand-off
requires it). See README-GARMIN-DEPLOY.md.

Env vars:
  SUPABASE_URL                your project URL, e.g. https://abc.supabase.co
  SUPABASE_SERVICE_ROLE_KEY   Supabase service-role secret (server only!)
  GARMIN_ENC_KEY              any long random string (encrypts stored tokens)
  PORT                        provided by Render
  GARMIN_SYNC_DAYS            optional, wellness look-back window (default 7)
"""

import os
import json
import time
import base64
import hashlib
import threading
import tempfile
import shutil
import traceback
import urllib.request
import urllib.error
from datetime import date, timedelta

import jwt
from jwt import PyJWKClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify
from garminconnect import Garmin

# ── Config ────────────────────────────────────────────────────────────────────
SERVICE_VERSION = "2026-07-13c"  # shown at /healthz — bump when app.py changes
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SERVICE_ROLE = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or ""
GARMIN_ENC_KEY = os.environ.get("GARMIN_ENC_KEY") or ""
PORT = int(os.environ.get("PORT") or 3002)
WELLNESS_DAYS = int(os.environ.get("GARMIN_SYNC_DAYS") or 7)
ACTIVITY_DAYS = 45
MFA_TTL_SECONDS = 300

app = Flask(__name__)


def configured():
    return bool(SUPABASE_URL and SERVICE_ROLE and GARMIN_ENC_KEY)


# ── Supabase auth (verify the signed-in user's ES256 token via JWKS) ──────────
_jwk_client = PyJWKClient(SUPABASE_URL + "/auth/v1/.well-known/jwks.json") if SUPABASE_URL else None


def verify_user(token):
    """Return the Supabase user id (sub) for a valid token, else None."""
    if not token or not _jwk_client:
        return None
    try:
        signing_key = _jwk_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token, signing_key.key,
            algorithms=["ES256", "RS256"],
            options={"verify_aud": False},
        )
        return payload.get("sub")
    except Exception:
        return None


# ── Token encryption (AES-256-GCM, key derived from GARMIN_ENC_KEY) ───────────
def _key():
    return hashlib.sha256(GARMIN_ENC_KEY.encode()).digest()


def encrypt_str(plaintext):
    iv = os.urandom(12)
    ct = AESGCM(_key()).encrypt(iv, plaintext.encode(), None)  # tag appended
    return base64.b64encode(iv + ct).decode()


def decrypt_str(b64):
    raw = base64.b64decode(b64)
    return AESGCM(_key()).decrypt(raw[:12], raw[12:], None).decode()


# ── Supabase REST (service role — bypasses RLS; server only) ──────────────────
def sb(method, path, body=None, prefer=None):
    url = SUPABASE_URL + "/rest/v1/" + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Content-Type": "application/json",
        "apikey": SERVICE_ROLE,
        "Authorization": "Bearer " + SERVICE_ROLE,
    }
    if prefer:
        headers["Prefer"] = prefer
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raise RuntimeError("Supabase %s on %s" % (e.code, path.split("?")[0]))


def load_tokens(user_id):
    rows = sb("GET", "garmin_tokens?user_id=eq.%s&select=tokens_enc,updated_at" % user_id)
    if not rows:
        return None
    try:
        return {"tokens": decrypt_str(rows[0]["tokens_enc"]), "updated_at": rows[0].get("updated_at")}
    except Exception:
        return None  # key changed / corrupt → treat as disconnected


def save_tokens(user_id, token_str):
    sb("POST", "garmin_tokens?on_conflict=user_id",
       [{"user_id": user_id, "tokens_enc": encrypt_str(token_str),
         "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}],
       prefer="resolution=merge-duplicates,return=minimal")


def delete_tokens(user_id):
    sb("DELETE", "garmin_tokens?user_id=eq.%s" % user_id)


# ── Garmin token (de)serialization ────────────────────────────────────────────
# Preferred: garth's documented single-string blob (dumps()/login(blob) — a
# string longer than 512 chars routes to garth.loads()). Fallback: the on-disk
# token-file pair. Restore understands both, plus legacy rows from the first
# build (a bare files dict).
def _auth_client(client):
    # The internal auth/token client is `.garth` in older garminconnect
    # releases and `.client` in current ones — support both.
    auth = getattr(client, "garth", None) or getattr(client, "client", None)
    if auth is None:
        raise RuntimeError("garminconnect exposed no auth client (.garth/.client)")
    return auth


def serialize_tokens(client):
    auth = _auth_client(client)
    try:
        blob = auth.dumps()
        if isinstance(blob, str) and len(blob) > 512:
            return json.dumps({"format": "dumps", "blob": blob})
    except Exception:
        pass  # fall through to the file-based store
    d = tempfile.mkdtemp(prefix="gc_")
    try:
        auth.dump(d)  # writes oauth1_token.json + oauth2_token.json
        files = {}
        for fn in os.listdir(d):
            with open(os.path.join(d, fn), "r") as fh:
                files[fn] = fh.read()
        return json.dumps({"format": "files", "files": files})
    finally:
        shutil.rmtree(d, ignore_errors=True)


def client_from_tokens(token_str):
    data = json.loads(token_str)
    if not isinstance(data, dict) or "format" not in data:
        data = {"format": "files", "files": data}  # legacy shape
    client = Garmin()
    if data["format"] == "dumps":
        client.login(data["blob"])  # >512 chars → garth.loads()
        return client
    d = tempfile.mkdtemp(prefix="gc_")
    try:
        for fn, content in (data.get("files") or {}).items():
            with open(os.path.join(d, fn), "w") as fh:
                fh.write(content)
        client.login(d)  # restore from token store (no password needed)
        return client
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ── Pending MFA logins (in-memory, single process) ────────────────────────────
_pending = {}
_pending_lock = threading.Lock()


class PendingLogin:
    def __init__(self, email, password):
        self.code = None
        self.code_ready = threading.Event()
        self.mfa_invoked = threading.Event()
        self.done = threading.Event()
        self.tokens = None
        self.error = None
        self.created = time.time()
        self._thread = threading.Thread(target=self._run, args=(email, password), daemon=True)

    def _prompt_mfa(self, *_args, **_kwargs):
        self.mfa_invoked.set()
        if not self.code_ready.wait(timeout=MFA_TTL_SECONDS - 20):
            raise TimeoutError("MFA code was not entered in time")
        return (self.code or "").strip()

    def _run(self, email, password):
        try:
            client = Garmin(email=email, password=password, prompt_mfa=self._prompt_mfa)
            client.login()
        except Exception as e:  # noqa: BLE001 — surface any login error to the caller
            self.error = "login: %s: %s" % (type(e).__name__, e)
            print("[garmin] login failed: %s" % e, flush=True)
            print(traceback.format_exc(), flush=True)
            self.done.set()
            return
        try:
            self.tokens = serialize_tokens(client)
        except Exception as e:  # login SUCCEEDED — do not blame the MFA code
            self.error = "token-save: %s: %s" % (type(e).__name__, e)
            print("[garmin] token serialization failed: %s" % e, flush=True)
            print(traceback.format_exc(), flush=True)
        finally:
            self.done.set()

    def start(self):
        self._thread.start()


def _sweep_pending():
    now = time.time()
    with _pending_lock:
        for uid in [k for k, p in _pending.items() if now - p.created > MFA_TTL_SECONDS]:
            _pending.pop(uid, None)


# ── Garmin data pull + normalization (matches the client's expected shape) ────
def _iso(d):
    return d.isoformat()


def _days_ago(n):
    return date.today() - timedelta(days=n)


def pull_all(client):
    warnings = []
    out = {"activities": [], "wellness": {"byDate": {}}, "trainingStatus": None,
           "vo2max": None, "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    def day(k):
        return out["wellness"]["byDate"].setdefault(k, {})

    # Activities
    try:
        acts = client.get_activities_by_date(_iso(_days_ago(ACTIVITY_DAYS)), _iso(date.today()))
        for a in (acts or []):
            atype = (a.get("activityType") or {}).get("typeKey") or "activity"
            start = str(a.get("startTimeLocal") or "")
            out["activities"].append({
                "id": "garmin-" + str(a.get("activityId")),
                "date": start[:10],
                "start_date_local": start.replace(" ", "T"),
                "name": a.get("activityName") or atype,
                "type": atype,
                "durationSeconds": int(a.get("duration") or 0),
                "calories": a.get("calories"),
                "avgHeartRate": a.get("averageHR"),
                "maxHeartRate": a.get("maxHR"),
                "distance": a.get("distance") or 0,  # meters
                "elevationGain": a.get("elevationGain"),
                "trainingLoad": a.get("activityTrainingLoad"),
                "aerobicTrainingEffect": a.get("aerobicTrainingEffect"),
                "anaerobicTrainingEffect": a.get("anaerobicTrainingEffect"),
                "trainingEffectLabel": a.get("trainingEffectLabel"),
                "source": "garmin",
            })
        out["activities"] = [a for a in out["activities"] if a["date"]]
    except Exception as e:
        warnings.append("activities: " + str(e))

    # Sleep (incl. stages), last N nights
    for i in range(WELLNESS_DAYS):
        ds = _iso(_days_ago(i))
        try:
            sleep = client.get_sleep_data(ds)
            dto = (sleep or {}).get("dailySleepDTO") or {}
            if dto.get("sleepTimeSeconds"):
                scores = dto.get("sleepScores") or {}
                overall = (scores.get("overall") or {}) if isinstance(scores, dict) else {}
                day(ds)["sleep"] = {
                    "totalSeconds": int(dto.get("sleepTimeSeconds") or 0),
                    "deepSeconds": int(dto.get("deepSleepSeconds") or 0),
                    "lightSeconds": int(dto.get("lightSleepSeconds") or 0),
                    "remSeconds": int(dto.get("remSleepSeconds") or 0),
                    "awakeSeconds": int(dto.get("awakeSleepSeconds") or 0),
                    "score": overall.get("value"),
                }
        except Exception as e:
            warnings.append("sleep %s: %s" % (ds, e))
            break

    # Body Battery (ranged)
    try:
        bb = client.get_body_battery(_iso(_days_ago(WELLNESS_DAYS - 1)), _iso(date.today()))
        for item in (bb or []):
            ds = item.get("date") or item.get("calendarValue") or item.get("calendarDate")
            if not ds:
                continue
            values = []
            for v in (item.get("bodyBatteryValuesArray") or []):
                try:
                    values.append(float(v[1] if isinstance(v, (list, tuple)) else v))
                except (TypeError, ValueError, IndexError):
                    pass
            day(ds)["bodyBattery"] = {
                "charged": item.get("charged"),
                "drained": item.get("drained"),
                "max": max(values) if values else None,
                "min": min(values) if values else None,
            }
    except Exception as e:
        warnings.append("bodyBattery: " + str(e))

    # HRV (nightly), last N days
    for i in range(WELLNESS_DAYS):
        ds = _iso(_days_ago(i))
        try:
            hrv = client.get_hrv_data(ds)
            s = (hrv or {}).get("hrvSummary") or {}
            if s.get("lastNightAvg") is not None or s.get("weeklyAvg") is not None:
                day(ds)["hrv"] = {
                    "lastNightAvg": s.get("lastNightAvg"),
                    "weeklyAvg": s.get("weeklyAvg"),
                    "status": s.get("status"),
                }
        except Exception as e:
            warnings.append("hrv %s: %s" % (ds, e))
            break

    # Training status (today)
    try:
        ts = client.get_training_status(_iso(date.today()))
        latest = None
        if isinstance(ts, dict):
            data = ts.get("latestTrainingStatusData") or {}
            if isinstance(data, dict) and data:
                latest = list(data.values())[0]
        if latest:
            out["trainingStatus"] = {
                "status": (str(latest.get("trainingStatus")) if latest.get("trainingStatus") is not None else None),
                "feedback": latest.get("trainingStatusFeedbackPhrase"),
            }
    except Exception as e:
        warnings.append("trainingStatus: " + str(e))

    # VO2 max (latest in window)
    try:
        mm = client.get_max_metrics(_iso(date.today()))
        latest = None
        for item in (mm or []):
            g = item.get("generic") if isinstance(item, dict) else None
            if g and (g.get("vo2MaxPreciseValue") is not None or g.get("vo2MaxValue") is not None):
                latest = g
        if latest:
            out["vo2max"] = {
                "value": latest.get("vo2MaxPreciseValue") or latest.get("vo2MaxValue"),
                "date": latest.get("calendarDate"),
            }
    except Exception as e:
        warnings.append("vo2max: " + str(e))

    if warnings:
        out["warnings"] = warnings
    return out


# ── Per-activity detail (HR zones, splits, HR trace, training effect) ─────────
# Lazy-fetched by the app the first time an activity's detail view opens, then
# cached client-side forever (a finished activity's data never changes).
ACTIVITY_TRACE_POINTS = 120  # Garmin downsamples server-side via maxChartSize


def _num_activity_id(raw):
    """Accept 'garmin-12345' or '12345'; return the numeric id string or None."""
    s = str(raw or "").strip()
    if s.startswith("garmin-"):
        s = s[len("garmin-"):]
    return s if s.isdigit() else None


def pull_activity_detail(client, aid):
    warnings = []
    out = {"id": "garmin-" + aid, "zones": None, "splits": None, "hrTrace": None,
           "trainingEffect": None,
           "syncedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # HR time in zones — NOTE: returns a JSON ARRAY despite the lib's dict hint
    try:
        zones = client.get_activity_hr_in_timezones(aid)
        norm = []
        for z in (zones or []):
            if not isinstance(z, dict) or z.get("secsInZone") is None:
                continue
            norm.append({"zone": z.get("zoneNumber"),
                         "secs": int(round(float(z["secsInZone"]))),
                         "lowBpm": z.get("zoneLowBoundary")})
        norm.sort(key=lambda z: z.get("zone") or 0)
        if norm:
            out["zones"] = norm
    except Exception as e:
        warnings.append("zones: " + str(e))

    # Splits / laps
    try:
        sp = client.get_activity_splits(aid) or {}
        laps = []
        for i, lap in enumerate(sp.get("lapDTOs") or []):
            if not isinstance(lap, dict):
                continue
            laps.append({
                "index": lap.get("lapIndex") or (i + 1),
                "distanceM": lap.get("distance"),
                "durationS": lap.get("duration"),
                "avgHeartRate": lap.get("averageHR"),
                "maxHeartRate": lap.get("maxHR"),
                "avgSpeed": lap.get("averageSpeed"),  # m/s
                "elevationGain": lap.get("elevationGain"),
                "calories": lap.get("calories"),
            })
        if laps:
            out["splits"] = laps
    except Exception as e:
        warnings.append("splits: " + str(e))

    # HR trace, downsampled by Garmin to <= ACTIVITY_TRACE_POINTS samples.
    # metricDescriptors order varies per device — never hardcode indexes.
    try:
        det = client.get_activity_details(aid, maxchart=ACTIVITY_TRACE_POINTS, maxpoly=0) or {}
        idx = {}
        for d in (det.get("metricDescriptors") or []):
            if isinstance(d, dict) and d.get("key") and d.get("metricsIndex") is not None:
                idx[d["key"]] = d["metricsIndex"]
        hi, ti, di = idx.get("directHeartRate"), idx.get("directTimestamp"), idx.get("sumDuration")
        trace = []
        t0 = None
        for row in (det.get("activityDetailMetrics") or []):
            m = (row or {}).get("metrics") or []
            hr = m[hi] if (hi is not None and hi < len(m)) else None
            if hr is None:
                continue  # sensor dropouts leave nulls
            sec = None
            if di is not None and di < len(m) and m[di] is not None:
                sec = float(m[di])
            elif ti is not None and ti < len(m) and m[ti] is not None:
                if t0 is None:
                    t0 = float(m[ti])
                sec = (float(m[ti]) - t0) / 1000.0  # GMT epoch ms → offset s
            trace.append([int(round(sec)) if sec is not None else None,
                          int(round(float(hr)))])
        if trace:
            out["hrTrace"] = trace
    except Exception as e:
        warnings.append("details: " + str(e))

    # Training effect from the full summary (sync already carries it for new
    # pulls, but older cached activities and dedup-merged records rely on this)
    try:
        summ = (client.get_activity(aid) or {}).get("summaryDTO") or {}
        if summ.get("aerobicTrainingEffect") is not None or summ.get("anaerobicTrainingEffect") is not None:
            out["trainingEffect"] = {
                "aerobic": summ.get("aerobicTrainingEffect"),
                "anaerobic": summ.get("anaerobicTrainingEffect"),
                "label": summ.get("trainingEffectLabel"),
            }
    except Exception as e:
        warnings.append("summary: " + str(e))

    if warnings:
        out["warnings"] = warnings
    return out


# ── HTTP ──────────────────────────────────────────────────────────────────────
@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp


@app.route("/healthz", methods=["GET"])
@app.route("/", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "service": "fitmind-garmin", "version": SERVICE_VERSION, "configured": configured()})


def _body():
    try:
        return json.loads(request.get_data(as_text=True) or "{}")
    except Exception:
        return {}


def _auth_or_401():
    if not configured():
        return None, (jsonify({"error": "Garmin service is not configured — set SUPABASE_URL, "
                                        "SUPABASE_SERVICE_ROLE_KEY and GARMIN_ENC_KEY."}), 501)
    body = _body()
    uid = verify_user(str(body.get("auth_token") or "").strip())
    if not uid:
        return None, (jsonify({"error": "Please sign in again — your session has expired."}), 401)
    return (uid, body), None


@app.route("/api/garmin/<path:_sub>", methods=["OPTIONS"])
def preflight(_sub):
    return ("", 204)


@app.route("/api/garmin/status", methods=["POST"])
def status():
    ctx, err = _auth_or_401()
    if err:
        return err
    uid, _ = ctx
    row = load_tokens(uid)
    return jsonify({"connected": bool(row), "updatedAt": row["updated_at"] if row else None})


@app.route("/api/garmin/connect", methods=["POST"])
def connect():
    ctx, err = _auth_or_401()
    if err:
        return err
    uid, body = ctx
    email = str(body.get("email") or "").strip()
    password = str(body.get("password") or "")
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    _sweep_pending()
    pending = PendingLogin(email, password)
    pending.start()

    # Wait briefly for one of: finished (no MFA), MFA prompt fired, or error.
    deadline = time.time() + 15
    while time.time() < deadline:
        if pending.done.is_set() or pending.mfa_invoked.is_set():
            break
        time.sleep(0.2)

    if pending.done.is_set():
        if pending.tokens:
            save_tokens(uid, pending.tokens)
            return jsonify({"status": "connected"})
        return jsonify({"error": _login_error_message(pending.error)}), _login_error_code(pending.error)

    if pending.mfa_invoked.is_set():
        with _pending_lock:
            _pending[uid] = pending
        return jsonify({"status": "mfa_required"})

    # Neither within 15s — abandon and ask to retry.
    return jsonify({"error": "Garmin took too long to respond — please try again."}), 504


@app.route("/api/garmin/mfa", methods=["POST"])
def mfa():
    ctx, err = _auth_or_401()
    if err:
        return err
    uid, body = ctx
    code = str(body.get("code") or "").strip()
    if not code:
        return jsonify({"error": "Enter the 6-digit code."}), 400

    with _pending_lock:
        pending = _pending.get(uid)
    if not pending or time.time() - pending.created > MFA_TTL_SECONDS:
        with _pending_lock:
            _pending.pop(uid, None)
        return jsonify({"error": "mfa_expired", "message": "That took too long — start the Garmin connection again."}), 400

    pending.code = code
    pending.code_ready.set()
    pending.done.wait(timeout=45)

    with _pending_lock:
        _pending.pop(uid, None)

    if not pending.done.is_set():
        return jsonify({"error": "Garmin is still processing — please try connecting again."}), 504
    if pending.tokens:
        save_tokens(uid, pending.tokens)
        return jsonify({"status": "connected"})
    # Surface the REAL reason (never contains credentials) so failures are
    # debuggable from the phone; full traceback is in the service logs.
    detail = str(pending.error or "no detail")[:220]
    print("[garmin] mfa flow failed for user %s: %s" % (uid, detail), flush=True)
    if detail.startswith("token-save:"):
        msg = "Garmin sign-in worked, but saving the connection failed — please report this: " + detail
    else:
        msg = "Garmin rejected the code or the sign-in — reconnect and use the newest code. (" + detail + ")"
    return jsonify({"error": msg}), 401


@app.route("/api/garmin/sync", methods=["POST"])
def sync():
    ctx, err = _auth_or_401()
    if err:
        return err
    uid, _ = ctx
    row = load_tokens(uid)
    if not row:
        return jsonify({"error": "not_connected"}), 400
    try:
        client = client_from_tokens(row["tokens"])
    except Exception as e:
        msg = str(e).lower()
        if any(w in msg for w in ("401", "403", "expired", "unauthor", "forbidden", "login")):
            return jsonify({"error": "garmin_reauth",
                            "message": "The Garmin connection has expired — reconnect it in your Profile."}), 401
        return jsonify({"error": "Garmin sync failed: " + str(e)}), 502
    try:
        data = pull_all(client)
        try:
            save_tokens(uid, serialize_tokens(client))  # persist any refreshed tokens
        except Exception:
            pass
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": "Garmin sync failed: " + str(e)}), 502


@app.route("/api/garmin/activity", methods=["POST"])
def activity_detail():
    ctx, err = _auth_or_401()
    if err:
        return err
    uid, body = ctx
    aid = _num_activity_id(body.get("activity_id"))
    if not aid:
        return jsonify({"error": "A numeric Garmin activity id is required."}), 400
    try:
        row = load_tokens(uid)
    except Exception as e:
        return jsonify({"error": "Could not read the Garmin connection: " + str(e)}), 502
    if not row:
        return jsonify({"error": "not_connected"}), 400
    try:
        client = client_from_tokens(row["tokens"])
    except Exception as e:
        msg = str(e).lower()
        if any(w in msg for w in ("401", "403", "expired", "unauthor", "forbidden", "login")):
            return jsonify({"error": "garmin_reauth",
                            "message": "The Garmin connection has expired — reconnect it in your Profile."}), 401
        return jsonify({"error": "Garmin detail failed: " + str(e)}), 502
    try:
        data = pull_activity_detail(client, aid)
        try:
            save_tokens(uid, serialize_tokens(client))  # persist any refreshed tokens
        except Exception:
            pass
        # Every section failed → surface a real error instead of a 200 the
        # client would cache forever (an all-null 200 WITHOUT warnings is a
        # legitimately empty activity and stays a 200).
        has_data = bool(data.get("zones") or data.get("splits") or data.get("hrTrace") or data.get("trainingEffect"))
        if not has_data and data.get("warnings"):
            joined = " ".join(data["warnings"]).lower()
            if "too many requests" in joined or "rate limit" in joined or "429" in joined:
                return jsonify({"error": "garmin_rate_limited",
                                "message": "Garmin is rate-limiting requests — try again in a few minutes."}), 429
            if any(w in joined for w in ("401", "403", "expired", "unauthor", "forbidden")):
                return jsonify({"error": "garmin_reauth",
                                "message": "The Garmin connection has expired — reconnect it in your Profile."}), 401
            return jsonify({"error": "Garmin detail failed: " + str(data["warnings"][0])[:200]}), 502
        return jsonify(data)
    except Exception as e:
        msg = str(e).lower()
        if "too many requests" in msg or "429" in msg:
            return jsonify({"error": "garmin_rate_limited",
                            "message": "Garmin is rate-limiting requests — try again in a few minutes."}), 429
        return jsonify({"error": "Garmin detail failed: " + str(e)}), 502


@app.route("/api/garmin/disconnect", methods=["POST"])
def disconnect():
    ctx, err = _auth_or_401()
    if err:
        return err
    uid, _ = ctx
    with _pending_lock:
        _pending.pop(uid, None)
    try:
        delete_tokens(uid)
    except Exception:
        pass
    return jsonify({"status": "disconnected"})


def _login_error_message(msg):
    m = (msg or "").lower()
    if "lock" in m:
        return "Garmin has temporarily locked sign-ins for this account — wait a while and try again."
    # Include the real reason (never contains credentials) for debuggability.
    return "Garmin sign-in failed — check the email and password. (" + str(msg or "no detail")[:220] + ")"


def _login_error_code(msg):
    return 429 if "lock" in (msg or "").lower() else 401


if __name__ == "__main__":
    # Single process, threaded (required: the MFA hand-off is in memory).
    app.run(host="0.0.0.0", port=PORT, threaded=True)
