# SafeNet API

Flask backend for [SafeNet](https://github.com/daleloncosky/safenet), a Rutgers hackathon phishing triage prototype from 2025. The code implements URL reputation checks, cautious handling of standalone email addresses, and AI-assisted review of message text.

## Supported behavior

| Input | Processing | Meaning of the result |
| --- | --- | --- |
| URL or domain with an optional path | Google Safe Browsing lookup | A listed threat, no known match, or an unavailable check |
| Standalone email address | Local input classification | `UNKNOWN`; the sender is not authenticated |
| Other text | OpenAI Chat Completions | An advisory assessment of possible phishing indicators |

This repository does not implement personal-data exposure searches or removal-request workflows. It does not assign a validated numerical risk score.

## Run locally

Use Python 3.11 or newer. Commands below use a POSIX shell.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python phishing_detector.py
```

Set `GOOGLE_API_KEY` to enable URL lookups and `OPENAI_API_KEY` to enable message review. `OPENAI_MODEL` defaults to `gpt-4.1-mini` and can be changed to a compatible model available to your account. API keys stay on the backend. The health endpoint works without either key; unconfigured checks report that limitation instead of preventing startup.

`PORT` defaults to 5000. `ALLOWED_ORIGINS` is a comma-separated list of exact frontend origins. The defaults include localhost and the original Vercel frontend recorded in the repository metadata. CORS controls browser access; it does not authenticate API clients.

## API

```sh
curl http://localhost:5000/health
curl -X POST http://localhost:5000/detect_phishing \
  -H 'Content-Type: application/json' \
  -d '{"text":"example.com"}'
```

Successful requests return an `analysis` string. URL and email responses also include a `status` such as `DANGER`, `NO_KNOWN_THREATS`, or `UNKNOWN`. Invalid JSON, wrong input types, and empty or overlong text return HTTP 400. Bodies over 16 KiB return 413. Missing text-analysis configuration returns 503; text-provider failures return 502 with a generic error.

## Validation

```sh
python -m unittest discover -s tests -v
```

Tests mock providers and require no real keys or paid API calls. They cover classification, malformed input, missing configuration, provider HTTP failures, secret-safe errors, and the difference between no match and verified safety.

## Deployment and limitations

```sh
gunicorn --bind 0.0.0.0:5000 phishing_detector:app
```

Use a host that provides HTTPS and set backend environment variables there. Configure application-level authentication or rate limits before exposing billable AI requests to untrusted traffic. This prototype does not include a user database, persistent storage, sender authentication, site crawling, or calibrated detection metrics. It sends URL data to Google and general message text to OpenAI. `store=False` is set for the model request; provider retention policies still apply. No live-provider accuracy evaluation is included.
