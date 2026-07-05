# PhishGuard

PhishGuard is a browser-based phishing detection system for FYP demonstration. It combines a local ML model, heuristic URL analysis, redirect checks, download risk detection, and URLHaus threat intelligence.

## Demo Links

Start the backend first, then use these links during the demo:

- Safe example: `https://www.example.com/`
- Suspicious login simulation: `http://127.0.0.1:5000/demo/suspicious-login?verify=account&brand=paypal&redirect=http://example.test`
- Malicious download simulation: `http://127.0.0.1:5000/demo/malicious-download.exe`

The malicious demo link is harmless and local. It triggers high risk because the URL ends with `.exe`, which your download-risk layer treats as dangerous.

## Training Dataset

`Data/Dataset.csv` is kept local and is not committed because threat-URL
datasets can contain credential-like strings that trigger repository secret
scanning. Place your local dataset at that path before running
`ModelTraining/train.py`. The pretrained model remains available for running
the application without retraining.

## URLHaus Refresh

The backend loads the local CSV at `Data/urlhaus.abuse.ch.csv`.

Before running the backend, install the backend dependencies:

```powershell
pip install -r Backend/requirements.txt
```

To enable manual or automatic refresh from URLHaus, set one of these before starting the backend:

```powershell
$env:URLHAUS_AUTH_KEY="your-urlhaus-auth-key"
```

or:

```powershell
$env:URLHAUS_CSV_URL="https://your-csv-feed.example/recent.csv"
```

Optional automatic refresh:

```powershell
$env:URLHAUS_AUTO_UPDATE="1"
$env:URLHAUS_UPDATE_INTERVAL_MINUTES="360"
```

Then start the backend and use the dashboard Intel tab to view status or manually refresh the feed.

If URLHaus update shows an SSL certificate verification error, run the dependency install command again so Python has the `certifi` certificate bundle. If your school or company network uses a custom certificate, set `URLHAUS_CA_BUNDLE` to that CA bundle file before starting the backend.
