import os
import json
import pickle
import logging
import argparse
import threading
import time
import ssl
import numpy as np
import pandas as pd

from flask           import Flask, request, jsonify
from flask_cors      import CORS
from datetime        import datetime, timezone
from urllib.parse    import urlparse
from urllib.request  import Request, urlopen

from feature_extractor import extract_features, features_to_list, FEATURE_COLS
from heuristic_engine  import run_full_heuristic_analysis
from risk_policy       import apply_navigation_context

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(message)s",
    datefmt= "%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)   # allows Chrome Extension to call this server

# ── Global model (loaded once at startup) ─────────────────────────────────────
_model    = None
_metadata = None
URLHAUS_SET = set()
URLHAUS_DOMAINS = set()
URLHAUS_LAST_LOADED_AT = None
URLHAUS_LAST_ERROR = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
URLHAUS_DEFAULT_PATH = os.path.join(PROJECT_ROOT, "Data", "urlhaus.abuse.ch.csv")
LOCAL_ENV_PATH = os.path.join(BASE_DIR, ".env")
URLHAUS_AUTH_ENV = "URLHAUS_AUTH_KEY"
URLHAUS_CSV_URL_ENV = "URLHAUS_CSV_URL"
URLHAUS_AUTO_UPDATE_ENV = "URLHAUS_AUTO_UPDATE"
URLHAUS_INTERVAL_ENV = "URLHAUS_UPDATE_INTERVAL_MINUTES"
URLHAUS_CA_BUNDLE_ENV = "URLHAUS_CA_BUNDLE"
DEFAULT_URLHAUS_INTERVAL_MINUTES = 360

DEMO_LINKS = {
    "safe": {
        "label": "Safe website example",
        "url": "https://www.example.com/",
        "description": "A normal reference website for showing a low-risk result.",
    },
    "suspicious": {
        "label": "Suspicious login simulation",
        "url": "http://127.0.0.1:5000/demo/suspicious-login?verify=account&brand=paypal&redirect=http://example.test",
        "description": "A harmless local page with suspicious URL patterns for warning demos.",
    },
    "malicious": {
        "label": "Malicious download simulation",
        "url": "http://127.0.0.1:5000/demo/malicious-download.exe",
        "description": "A harmless local page that uses a dangerous-looking extension to trigger high risk.",
    },
}

def load_local_env(path=LOCAL_ENV_PATH):
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key and key not in os.environ:
                os.environ[key] = value

load_local_env()

# =============================================================================
# Load Model
# =============================================================================

def load_model(model_path):
    global _model, _metadata

    log.info("Loading model from: %s", model_path)

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model file not found: {model_path}\n"
            f"Make sure you downloaded model_output/ from EC2 first."
        )

    print("LOADING MODEL:", model_path)

    with open(model_path, "rb") as f:
        _model = pickle.load(f)

    print("=" * 80)
    print("MODEL TYPE:", type(_model))
    print("MODEL OBJECT:", _model)

    if hasattr(_model, "classes_"):
        print("CLASSES:", _model.classes_)

    print("=" * 80)

    # Load metadata from same folder
    meta_path = os.path.join(os.path.dirname(model_path), "metadata.json")
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            _metadata = json.load(f)
        log.info("Best model   : %s", _metadata.get("best_model"))
        log.info("F1 Score     : %s", _metadata.get("best_scores", {}).get("f1"))
        log.info("Accuracy     : %s", _metadata.get("best_scores", {}).get("accuracy"))
    else:
        log.warning("metadata.json not found — model loaded without metadata")

    log.info("Model loaded successfully")


# =============================================================================
# Risk Score Helpers
# =============================================================================

def get_domain(url):
    return (urlparse(url).hostname or "").replace("www.", "")

def iso_datetime(timestamp):
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

def get_demo_links():
    return DEMO_LINKS

def build_urlhaus_download_url(auth_key=None, override_url=None):
    override_url = (
        os.getenv(URLHAUS_CSV_URL_ENV, "") if override_url is None else override_url
    ).strip()
    if override_url:
        return override_url

    auth_key = (
        os.getenv(URLHAUS_AUTH_ENV, "") if auth_key is None else auth_key
    ).strip()
    if not auth_key:
        return None

    return f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"

def get_urlhaus_ca_bundle_path(ca_bundle=None):
    ca_bundle = (
        os.getenv(URLHAUS_CA_BUNDLE_ENV, "") if ca_bundle is None else ca_bundle
    ).strip()
    if ca_bundle:
        return ca_bundle

    try:
        import certifi
    except ImportError:
        return None

    return certifi.where()

def create_urlhaus_ssl_context(ca_bundle=None):
    ca_bundle_path = get_urlhaus_ca_bundle_path(ca_bundle)
    if ca_bundle_path:
        return ssl.create_default_context(cafile=ca_bundle_path)
    return ssl.create_default_context()

def format_urlhaus_download_error(error):
    message = str(error)
    if "CERTIFICATE_VERIFY_FAILED" in message:
        return (
            "URLHaus SSL certificate verification failed. Run "
            "`pip install -r Backend/requirements.txt` to install/update the "
            "certificate bundle, then restart the backend. If your network uses "
            "a custom school or company certificate, set URLHAUS_CA_BUNDLE to "
            "that CA bundle file."
        )
    return message

def get_urlhaus_status(source_path=URLHAUS_DEFAULT_PATH):
    source_path = os.path.abspath(source_path)
    file_exists = os.path.exists(source_path)
    modified_at = os.path.getmtime(source_path) if file_exists else None

    return {
        "provider": "URLHaus",
        "loaded_urls": len(URLHAUS_SET),
        "loaded_domains": len(URLHAUS_DOMAINS),
        "source_file": source_path,
        "file_exists": file_exists,
        "file_modified_at": iso_datetime(modified_at),
        "last_loaded_at": URLHAUS_LAST_LOADED_AT,
        "last_error": URLHAUS_LAST_ERROR,
        "update_configured": bool(build_urlhaus_download_url()),
        "auto_update_enabled": os.getenv(URLHAUS_AUTO_UPDATE_ENV, "").strip() == "1",
    }

def update_urlhaus_dataset(source_url=None, destination_path=URLHAUS_DEFAULT_PATH):
    global URLHAUS_LAST_ERROR

    source_url = source_url or build_urlhaus_download_url()
    if not source_url:
        URLHAUS_LAST_ERROR = (
            "URLHaus update is not configured. Set URLHAUS_AUTH_KEY or URLHAUS_CSV_URL."
        )
        raise RuntimeError(URLHAUS_LAST_ERROR)

    destination_path = os.path.abspath(destination_path)
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    temp_path = destination_path + ".download"

    req = Request(
        source_url,
        headers={"User-Agent": "PhishGuard-FYP/1.0 URLHaus updater"},
    )

    try:
        with urlopen(req, timeout=30, context=create_urlhaus_ssl_context()) as response:
            content = response.read()

        if not content.strip():
            raise RuntimeError("Downloaded URLHaus file was empty.")

        with open(temp_path, "wb") as f:
            f.write(content)

        os.replace(temp_path, destination_path)
        load_urlhaus(destination_path)
        URLHAUS_LAST_ERROR = None
        return get_urlhaus_status(destination_path)
    except Exception as exc:
        URLHAUS_LAST_ERROR = format_urlhaus_download_error(exc)
        if os.path.exists(temp_path):
            os.remove(temp_path)
        if URLHAUS_LAST_ERROR != str(exc):
            raise RuntimeError(URLHAUS_LAST_ERROR) from exc
        raise

def start_urlhaus_auto_updater():
    if os.getenv(URLHAUS_AUTO_UPDATE_ENV, "").strip() != "1":
        return

    source_url = build_urlhaus_download_url()
    if not source_url:
        log.warning(
            "URLHaus auto update requested but no source is configured. "
            "Set URLHAUS_AUTH_KEY or URLHAUS_CSV_URL."
        )
        return

    try:
        interval_minutes = int(
            os.getenv(URLHAUS_INTERVAL_ENV, DEFAULT_URLHAUS_INTERVAL_MINUTES)
        )
    except ValueError:
        interval_minutes = DEFAULT_URLHAUS_INTERVAL_MINUTES

    interval_seconds = max(interval_minutes, 5) * 60

    def loop():
        while True:
            time.sleep(interval_seconds)
            try:
                update_urlhaus_dataset(source_url=source_url)
                log.info("URLHaus auto update completed")
            except Exception as exc:
                log.warning("URLHaus auto update failed: %s", exc)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    log.info("URLHaus auto updater enabled: every %d minutes", interval_minutes)

def calculate_risk_score(ml_proba, heuristic_risk, urlhaus_hit, download_info):
    download_factor = 0.0

    if download_info.get("is_malicious"):
        download_factor = 1.0
    elif download_info.get("is_suspicious"):
        download_factor = 0.5

    # If confirmed by threat intelligence, high risk immediately
    if urlhaus_hit or download_info.get("is_malicious"):
        return 95.0

    # If heuristic is very low, don't let ML alone dominate
    adjusted_ml = ml_proba
    if heuristic_risk < 0.15:
        adjusted_ml *= 0.55

    raw = (
        0.55 * adjusted_ml +
        0.35 * heuristic_risk +
        0.10 * download_factor
    )

    score = min(max(raw * 100, 0), 100)

    # Suspicious archives should never be presented as fully safe.
    if download_info.get("is_suspicious"):
        score = max(score, 45.0)

    return round(score, 1)

def get_status_from_score(score):
    if score >= 70:
        return "phishing"
    elif score >= 40:
        return "suspicious"
    return "safe"

def get_risk_level(score, is_phishing, download_info):
    """Convert score to LOW / MEDIUM / HIGH."""
    if download_info.get("is_malicious"):
        return "HIGH"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "HIGH" if is_phishing else "MEDIUM"
    return "LOW"


def load_urlhaus(path=URLHAUS_DEFAULT_PATH):
    global URLHAUS_SET, URLHAUS_DOMAINS, URLHAUS_LAST_LOADED_AT, URLHAUS_LAST_ERROR

    if not os.path.exists(path):
        URLHAUS_SET = set()
        URLHAUS_DOMAINS = set()
        URLHAUS_LAST_ERROR = f"URLHaus file not found: {path}"
        log.warning("URLHaus file not found: %s", path)
        return

    # URLHaus CSV has comments at top
    df = pd.read_csv(path, comment="#", header=None)

    # column 2 usually contains URLs
    urls = df[2].dropna().astype(str)

    URLHAUS_SET = set(urls)
    URLHAUS_DOMAINS = set()

    # also store domains (better detection)
    for url in urls:
        try:
            domain = urlparse(url).netloc
            if domain:
                URLHAUS_DOMAINS.add(domain)
        except:
            pass

    URLHAUS_LAST_LOADED_AT = datetime.now(timezone.utc).isoformat()
    URLHAUS_LAST_ERROR = None

    print(f"[URLHaus] Loaded URLs: {len(URLHAUS_SET)}")
    print(f"[URLHaus] Loaded domains: {len(URLHAUS_DOMAINS)}")

def check_urlhaus(url):
    domain = urlparse(url).netloc

    # exact match
    if url in URLHAUS_SET:
        return True

    # domain match
    if domain in URLHAUS_DOMAINS:
        return True

    return False


def get_recommended_action(status, download_info):
    if download_info.get("is_malicious"):
        return "block_download"
    if status == "phishing":
        return "block_page"
    if status == "suspicious" or download_info.get("is_suspicious"):
        return "warn"
    return "allow"

def get_top_features(features_dict, n=5):
    """Return top N features by model importance."""
    if _metadata and _metadata.get("feature_importance"):
        top_names = list(_metadata["feature_importance"].keys())[:n]
    else:
        top_names = FEATURE_COLS[:n]
    return {name: round(features_dict.get(name, 0.0), 4) for name in top_names}


# =============================================================================
# Routes
# =============================================================================

@app.route("/", methods=["GET"])
def index():
    """Health check — open http://localhost:5000 in browser to confirm running."""
    model_name = _metadata.get("best_model", "unknown") if _metadata else "unknown"
    return jsonify({
        "status"     : "running",
        "service"    : "PhishGuard Backend",
        "model"      :  model_name,
        "endpoint"   : "POST /analyze",
        "threat_intel": "GET /threat-intel/status",
        "demo_links" : "GET /demo-links",
    })


@app.route("/demo-links", methods=["GET"])
def demo_links():
    return jsonify(get_demo_links())


@app.route("/threat-intel/status", methods=["GET"])
def threat_intel_status():
    return jsonify(get_urlhaus_status())


@app.route("/threat-intel/update", methods=["POST", "OPTIONS"])
def threat_intel_update():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    try:
        status = update_urlhaus_dataset()
        return jsonify({
            "ok": True,
            "message": "URLHaus database refreshed successfully.",
            "urlhaus": status,
        })
    except Exception as exc:
        return jsonify({
            "ok": False,
            "message": str(exc),
            "urlhaus": get_urlhaus_status(),
        }), 400


@app.route("/demo", methods=["GET"])
def demo_page():
    links = get_demo_links()
    rows = "\n".join(
        f'<li><a href="{item["url"]}">{item["label"]}</a><p>{item["description"]}</p></li>'
        for item in links.values()
    )
    return f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>PhishGuard Demo Links</title>
        <style>
          body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: #0f172a;
            color: #e5e7eb;
            padding: 32px;
          }}
          main {{
            max-width: 760px;
            margin: 0 auto;
          }}
          a {{
            color: #67e8f9;
            font-weight: 700;
          }}
          li {{
            margin: 18px 0;
            padding: 16px;
            border: 1px solid #334155;
            border-radius: 8px;
            background: #111827;
          }}
          p {{
            color: #94a3b8;
            margin: 8px 0 0;
          }}
        </style>
      </head>
      <body>
        <main>
          <h1>PhishGuard Demo Links</h1>
          <p>These links are local or harmless references for classroom demonstration.</p>
          <ul>{rows}</ul>
        </main>
      </body>
    </html>
    """


@app.route("/demo/suspicious-login", methods=["GET", "HEAD"])
def demo_suspicious_login():
    return """
    <!doctype html>
    <html lang="en">
      <head><title>Suspicious Login Demo</title></head>
      <body>
        <h1>Suspicious login simulation</h1>
        <p>This is a harmless local demo page used to trigger warning indicators.</p>
      </body>
    </html>
    """


@app.route("/demo/malicious-download.exe", methods=["GET", "HEAD"])
def demo_malicious_download():
    return (
        """
        <!doctype html>
        <html lang="en">
          <head><title>Malicious Download Simulation</title></head>
          <body>
            <h1>Malicious download simulation</h1>
            <p>This is a harmless local page. The .exe path is only for detector demo.</p>
          </body>
        </html>
        """,
        200,
        {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )


@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    """
    Main endpoint — called by Chrome Extension.

    Request body:
      { "url": "https://example.com" }

    Response:
      {
        "url"            : original URL,
        "resolved_url"   : after following redirects,
        "risk_score"     : 0-100,
        "risk_level"     : LOW | MEDIUM | HIGH,
        "is_phishing"    : true/false,
        "ml_confidence"  : 0-100 (ML model %),
        "heuristic_risk" : 0-100 (heuristic %),
        "flags"          : [warning strings],
        "was_shortened"  : true/false,
        "redirect_count" : number,
        "download"       : { is_malicious, extension, message },
        "model_used"     : model name,
        "top_features"   : { feature: value },
      }
    """
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return jsonify({}), 200

    # ── Parse request ─────────────────────────────────────────────────────────
    try:
        body = request.get_json(force=True, silent=True) or {}
        url  = body.get("url", "").strip()
        filename = body.get("filename", "")
        navigation_context = {
            "unexpected_cross_domain_tab": bool(body.get("unexpected_redirect")),
        }
        if not url:
            return jsonify({"error": "Missing 'url' in request"}), 400
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    log.info("Analyzing: %s", url[:120])

    # =========================================================================
    # LAYER 1 — ML Model Prediction
    # =========================================================================
    try:
        features_dict = extract_features(url)

        log.info("SMOTE CHECK: inference phase (NO resampling)")
        log.info("FEATURE COUNT: %d", len(features_dict))

        # IMPORTANT: enforce correct feature order
        X = pd.DataFrame([[features_dict[col] for col in FEATURE_COLS]],columns=FEATURE_COLS)

        for col in FEATURE_COLS:
             print(col, "=", features_dict[col])

        log.info("FEATURE SHAPE: %s", X.shape)

        # check pipeline type (for debugging only)
        if hasattr(_model, "named_steps"):
            log.info("Pipeline detected: YES")
        else:
            log.info("Pipeline detected: NO")

        print("X TYPE:", type(X))
        print("X SHAPE:", X.shape)

        proba = _model.predict_proba(X)

        print("RAW PROBA:", proba)
        print("PROBA TYPE:", type(proba))
        print("PROBA SHAPE:", proba.shape)
        ml_proba = float(proba[0][1]) 

        # phishing class probability (assuming class 1 = phishing)
        ml_proba = np.clip(ml_proba, 0.0, 1.0)

        pred = _model.predict(X)[0]
        print("PREDICT:", _model.predict(X))
        print("PROBA:", _model.predict_proba(X))
        print("CLASSES:", _model.classes_)
        is_phishing = ml_proba >= 0.7

        log.info("ML: proba=%.4f phishing=%s", ml_proba, is_phishing)

    except Exception as e:
        log.error("ML error: %s", e)
        return jsonify({"error": "ML prediction failed"}), 500


    # =========================================================================
    # LAYER 2 — Heuristic Analysis
    # (unshortens URL, checks download, runs all rules)
    # =========================================================================
    try:
        heuristic = run_full_heuristic_analysis(url, filename=filename)
        log.info(
            "Heuristic: risk=%.4f flags=%d redirects=%d",
            heuristic["heuristic_risk"],
            len(heuristic["flags"]),
            heuristic["redirect_count"],
        )
    except Exception as e:
        log.error("Heuristic error: %s", e)
        heuristic = {
            "resolved_url"  : url,
            "was_shortened" : False,
            "redirect_count": 0,
            "redirect_chain": [url],
            "cross_domain"  : False,
            "flags"         : [],
            "download"      : {
                "is_malicious" : False,
                "is_suspicious": False,
                "extension"    : None,
                "severity"     : None,
                "message"      : None,
            },
            "heuristic_risk": 0.0,
            "rule_scores"   : {},
        }

    # =========================================================================
    # LAYER 3 — Combine into final score
    # =========================================================================
    download_info = heuristic["download"]
    urlhaus_hit = check_urlhaus(url) or check_urlhaus(heuristic["resolved_url"])
    print("URLHAUS HIT:", urlhaus_hit)
    risk_score = calculate_risk_score(
        ml_proba,
        heuristic["heuristic_risk"],
        urlhaus_hit,
        download_info
    )
    risk_score = apply_navigation_context(risk_score, navigation_context)

    status = get_status_from_score(risk_score)
    is_phishing = status == "phishing"
    risk_level = get_risk_level(risk_score, is_phishing, download_info)
    recommended_action = get_recommended_action(status, download_info)

    model_name = (
        _metadata.get("best_model", "unknown") if _metadata else "unknown"
    )

    flags = heuristic["flags"].copy()

    if urlhaus_hit:
        flags.append("URL found in URLHaus database")
    if navigation_context["unexpected_cross_domain_tab"]:
        flags.append(
            "Deceptive behavior: an unexpected cross-domain advertisement tab "
            "was opened after a page click"
        )

    result = {
        "url"            : url,
        "resolved_url"   : heuristic["resolved_url"],
        "risk_score"     : risk_score,
        "urlhaus_hit"    : bool(urlhaus_hit),
        "risk_level"     : risk_level,
        "status"         : status,
        "is_phishing"    : bool(is_phishing),
        "recommended_action": recommended_action,
        "ml_confidence"  : round(ml_proba * 100, 1),
        "heuristic_risk" : round(heuristic["heuristic_risk"] * 100, 1),
        "flags"          : flags,
        "was_shortened"  : heuristic["was_shortened"],
        "redirect_count" : heuristic["redirect_count"],
        "redirect_chain" : heuristic["redirect_chain"],
        "cross_domain"   : heuristic["cross_domain"],
        "download"       : {
            "is_malicious" : download_info.get("is_malicious",  False),
            "is_suspicious": download_info.get("is_suspicious", False),
            "extension"    : download_info.get("extension"),
            "severity"     : download_info.get("severity"),
            "message"      : download_info.get("message"),
        },
        "model_used"     : model_name,
        "top_features"   : get_top_features(features_dict),
    }

    log.info("Result: score=%.1f level=%s", risk_score, risk_level)
    return jsonify(result), 200


# =============================================================================
# Startup
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PhishGuard Flask Backend"
    )
    parser.add_argument(
        "--model",
        default = "../ModelTraining/Model_Output/model.pkl",
        help    = "Path to trained model.pkl file"
    )
    parser.add_argument(
        "--port",
        type    = int,
        default = 5000,
        help    = "Port to run server on (default: 5000)"
    )
    args = parser.parse_args()

    # Load model before starting server
    load_model(args.model)
    load_urlhaus() 
    start_urlhaus_auto_updater()

    print("MODEL TYPE:", type(_model))
    print("MODEL CLASS:", _model.__class__.__name__)

    if hasattr(_model, "classes_"):
        print("CLASSES:", _model.classes_)

    if hasattr(_model, "n_features_in_"):
        print("FEATURE COUNT:", _model.n_features_in_)

    log.info("")
    log.info("╔══════════════════════════════════════════════════════╗")
    log.info("║         PhishGuard Backend Server                    ║")
    log.info("╠══════════════════════════════════════════════════════╣")
    log.info("║  Running at : http://localhost:%d                  ║", args.port)
    log.info("║  Endpoint   : POST http://localhost:%d/analyze     ║", args.port)
    log.info("║                                                      ║")
    log.info("║  Keep this terminal open while using the extension   ║")
    log.info("║  Press Ctrl+C to stop the server                     ║")
    log.info("╚══════════════════════════════════════════════════════╝")

    app.run(
        host  = "127.0.0.1",
        port  = args.port,
        debug = False,
    )
