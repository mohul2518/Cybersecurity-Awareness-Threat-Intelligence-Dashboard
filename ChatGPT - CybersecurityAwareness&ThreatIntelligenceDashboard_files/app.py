"""
Cybersecurity Awareness & Threat Intelligence Dashboard
=======================================================
DEFENSIVE, EDUCATIONAL project. All data is synthetic / fictional.
The app NEVER connects to any IP, domain or URL it stores or is asked
to search. Every lookup is a local database query only.

Sections
  1  Configuration & security headers
  2  Constants
  3  Intelligence engines (pure functions - easy to unit test)
       validate_indicator, calculate_confidence, calculate_threat_risk,
       classify_risk, classify_record, correlate_threats,
       generate_threat_alert, correlate_alerts,
       calculate_vulnerability_priority, enrich_indicator,
       score_quiz, generate_learning_recommendations
  4  Database (schema, migration, synthetic data)
  5  Auth, roles, audit log
  6  Page layout
  7  Pages: dashboard, IOC search, threat detail, alerts, SOC,
            correlation, ATT&CK, CVE, awareness, quiz, executive, IR guide
  8  REST API
  9  CLI commands
"""

import csv
import hashlib
import io
import ipaddress
import json
import os
import random
import re
import sqlite3
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from functools import wraps
from getpass import getpass
from pathlib import Path
from urllib.parse import urlencode, urlparse

from dotenv import load_dotenv
from flask import (
    Flask, Response, abort, jsonify, redirect,
    render_template_string, request, url_for
)
from flask_login import (
    LoginManager, UserMixin, current_user, login_user, logout_user
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


# ============================================================
# 1. CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("THREATS_DB", BASE_DIR / "threats.db"))
SCHEMA_VERSION = 2

load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY is missing. Create a .env file beside app.py.")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"

csrf = CSRFProtect(app)


@app.after_request
def add_security_headers(response):
    """Baseline browser security headers (no external scripts are used)."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
    return response


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message = "Please log in first."


# ============================================================
# 2. CONSTANTS
# ============================================================

SEVERITIES = ("Informational", "Low", "Medium", "High", "Critical")
TYPES = ("IP", "Domain", "URL", "Hash", "Email Domain", "CVE")
CATEGORIES = (
    "Phishing", "Malware", "Ransomware", "Credential Threats", "Web Threats",
    "Network Threats", "Vulnerability Exposure", "Social Engineering",
    "Data Exposure", "Account Security",
)
IND_STATUSES = ("NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE")
ALERT_STATUSES = ("NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE")
ROLES = ("viewer", "analyst", "admin")

# Source -> reliability grade. Reliability of a SOURCE is not the same as
# confidence in one specific intelligence ITEM.
SOURCES = {
    "Internal SOC": "A", "Security Vendor": "B", "Research Report": "B",
    "Public Threat Feed": "C", "Community Submission": "C", "Unknown Source": "D",
}
RELIABILITY_LABELS = {
    "A": "Highly Reliable", "B": "Usually Reliable",
    "C": "Fairly Reliable", "D": "Reliability Unknown",
}

# ATT&CK mapping, applied ONLY when context is sufficient.
# Social Engineering and Vulnerability Exposure are deliberately unmapped.
CATEGORY_ATTACK = {
    "Phishing": ("Initial Access", "T1566", "Phishing"),
    "Malware": ("Execution", "T1059", "Command and Scripting Interpreter"),
    "Ransomware": ("Impact", "T1486", "Data Encrypted for Impact"),
    "Credential Threats": ("Credential Access", "T1110", "Brute Force"),
    "Web Threats": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "Network Threats": ("Command and Control", "T1071", "Application Layer Protocol"),
    "Data Exposure": ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    "Account Security": ("Initial Access", "T1078", "Valid Accounts"),
}

TYPE_BY_CATEGORY = {
    "Phishing": ("Domain", "URL", "Email Domain", "IP"),
    "Malware": ("Hash", "IP", "Domain"),
    "Ransomware": ("Hash", "IP", "Domain"),
    "Credential Threats": ("IP", "Domain", "Email Domain"),
    "Web Threats": ("URL", "IP", "Domain"),
    "Network Threats": ("IP", "Domain"),
    "Vulnerability Exposure": ("CVE",),
    "Social Engineering": ("Email Domain", "Domain", "URL"),
    "Data Exposure": ("Domain", "URL", "IP"),
    "Account Security": ("IP", "Email Domain"),
}

# Defensive actions only. No exploitation or offensive steps.
RECOMMENDED_ACTIONS = {
    "Phishing": ["Review email-security telemetry for related messages",
                 "Check for authorized sightings before blocking",
                 "Run a phishing awareness reminder", "Monitor for related indicators"],
    "Malware": ["Review endpoint-protection logs for related detections",
                "Confirm patch and AV status on affected assets", "Do not execute or open the file"],
    "Ransomware": ["Verify backups are recent and restorable", "Review privileged access and segmentation",
                   "Prepare incident-response contacts"],
    "Credential Threats": ["Review failed-login patterns in internal logs", "Enforce MFA on exposed accounts",
                           "Prompt password resets where justified"],
    "Web Threats": ["Review web-gateway and proxy logs", "Check WAF rules and patch levels"],
    "Network Threats": ["Review firewall and DNS logs for authorized sightings", "Check segmentation rules"],
    "Vulnerability Exposure": ["Check which assets run the affected product", "Prioritize by exposure and exploitation evidence"],
    "Social Engineering": ["Remind staff to verify unusual requests via a known channel", "Review reporting channels"],
    "Data Exposure": ["Review access controls on the exposed data", "Follow the data-incident process"],
    "Account Security": ["Review recent sign-ins for the affected accounts", "Confirm MFA is enforced"],
}

DEMO_CVE_IDS = [f"CVE-2099-{n:04d}" for n in range(1, 21)]  # fictional year 2099


# ============================================================
# 3. INTELLIGENCE ENGINES
# ============================================================

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def validate_indicator(value):
    """
    Syntax-only validation. Answers "is this well-formed?" and NOT
    "is this malicious?". Never contacts any external system.
    """
    value = (value or "").strip()
    result = {"valid": False, "indicator_type": None,
              "normalized_value": value, "validation_notes": ""}

    def ok(kind, normalized, note):
        result.update(valid=True, indicator_type=kind,
                      normalized_value=normalized, validation_notes=note)
        return result

    if not value:
        result["validation_notes"] = "Indicator cannot be empty."
        return result

    try:
        ip = ipaddress.ip_address(value)
        return ok("IP", ip.compressed, f"Valid IPv{ip.version} syntax.")
    except ValueError:
        pass

    try:
        parsed = urlparse(value)
        if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
            host = parsed.hostname
            try:
                ipaddress.ip_address(host)
                host_ok = True
            except ValueError:
                host_ok = bool(DOMAIN_PATTERN.fullmatch(host.lower()))
            if host_ok:
                return ok("URL", value, "Valid HTTP/HTTPS URL syntax. No network connection was made.")
    except ValueError:
        pass

    for length, name in ((32, "MD5"), (40, "SHA-1"), (64, "SHA-256")):
        if re.fullmatch(rf"[A-Fa-f0-9]{{{length}}}", value):
            return ok("Hash", value.lower(), f"Valid {name}-format hash.")

    if CVE_PATTERN.fullmatch(value):
        return ok("CVE", value.upper(), "Valid CVE identifier syntax.")

    if DOMAIN_PATTERN.fullmatch(value.lower()):
        return ok("Domain", value.lower(), "Valid domain syntax.")

    result["validation_notes"] = ("Invalid IOC syntax. Supported: IPv4, IPv6, domain, "
                                  "URL, MD5, SHA-1, SHA-256, CVE.")
    return result


def clamp(x, low=0, high=100):
    return max(low, min(high, x))


def calculate_confidence(reliability, observations, age_days, corroboration):
    """
    Confidence (0-100) = how much we trust THIS piece of intelligence.
    Inputs: source reliability grade, repeat observations, corroborating
    sources, and staleness. (Risk is a different question - see below.)
    """
    base = {"A": 70, "B": 58, "C": 45, "D": 30}.get(reliability, 30)
    base += min(observations, 20) * 0.8
    base += min(corroboration, 5) * 3
    base -= max(0, age_days - 30) * 0.3
    return int(clamp(round(base)))


SEVERITY_POINTS = {"Informational": 10, "Low": 25, "Medium": 50, "High": 75, "Critical": 100}
RELIABILITY_POINTS = {"A": 100, "B": 75, "C": 50, "D": 25}


def calculate_threat_risk(severity, confidence, last_seen_iso, observations,
                          reliability, related_alerts, now=None):
    """
    Risk (0-100) = how concerning the item may be.
    Weights: severity 30, confidence 25, recency 15, observation
    frequency 10, source reliability 10, context/correlation 10.
    HIGH RISK DOES NOT MEAN CONFIRMED COMPROMISE.
    """
    now = now or datetime.now()
    try:
        age = (now - datetime.fromisoformat(last_seen_iso)).days
    except (TypeError, ValueError):
        age = 90
    recency = clamp(100 - max(age, 0) * 100 / 90)
    frequency = min(observations, 20) / 20 * 100
    context = min(related_alerts, 5) / 5 * 100
    score = (0.30 * SEVERITY_POINTS.get(severity, 0) + 0.25 * confidence
             + 0.15 * recency + 0.10 * frequency
             + 0.10 * RELIABILITY_POINTS.get(reliability, 25) + 0.10 * context)
    return int(clamp(round(score)))


def classify_risk(score):
    if score <= 20:
        return "INFORMATIONAL"
    if score <= 40:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 80:
        return "HIGH"
    return "CRITICAL"


def interpret_scores(risk, confidence):
    """Plain-language reading of risk vs confidence."""
    if risk >= 61 and confidence < 40:
        return "Potentially serious, but evidence quality is weak. Validate before acting."
    if risk >= 61 and confidence >= 60:
        return "High-confidence intelligence with meaningful risk. Prioritize investigation."
    if risk < 41 and confidence >= 60:
        return "Well-supported intelligence, but low concern. Monitor."
    return "Moderate concern or moderate evidence. Review with context."


def classify_record(confidence, risk, cluster_size, has_alert, has_incident):
    """
    Keep the five levels distinct (an indicator is NOT a confirmed attack):
      OBSERVATION - raw, low-confidence sighting
      INDICATOR   - enough confidence to track as an IOC
      ALERT       - a rule fired; an analyst should triage
      THREAT      - alerted + corroborated by a related cluster
      INCIDENT    - only when an analyst explicitly declares one
    """
    if has_incident:
        return "INCIDENT"
    if has_alert and cluster_size >= 3 and confidence >= 60 and risk >= 61:
        return "THREAT"
    if has_alert:
        return "ALERT"
    if confidence >= 40:
        return "INDICATOR"
    return "OBSERVATION"


def correlate_threats(rows, gap_days=14):
    """
    Group records into RELATED THREAT CLUSTERS: same campaign_id and the
    same observation window (no gap larger than gap_days).
    Correlation shows relationship, NOT guaranteed attribution.
    """
    groups = defaultdict(list)
    for r in rows:
        if r["campaign_id"]:
            groups[r["campaign_id"]].append(r)

    clusters = []
    for cid, items in groups.items():
        items = sorted(items, key=lambda r: r["first_seen"])
        windows, current = [], [items[0]]
        for prev, cur in zip(items, items[1:]):
            gap = datetime.fromisoformat(cur["first_seen"]) - datetime.fromisoformat(prev["first_seen"])
            if gap > timedelta(days=gap_days):
                windows.append(current)
                current = []
            current.append(cur)
        windows.append(current)

        for n, members in enumerate(windows, 1):
            if len(members) < 2:
                continue
            clusters.append({
                "cluster_id": f"{cid}-W{n}", "campaign_id": cid,
                "category": members[0]["category"], "size": len(members),
                "types": sorted({m["type"] for m in members}),
                "max_risk": max(m["risk_score"] for m in members),
                "avg_conf": round(sum(m["confidence_score"] for m in members) / len(members)),
                "first_seen": members[0]["first_seen"],
                "last_seen": max(m["last_seen"] for m in members),
                "member_ids": [m["id"] for m in members],
            })
    return sorted(clusters, key=lambda c: (-c["max_risk"], c["cluster_id"]))


def generate_threat_alert(ind, cluster_size):
    """Return candidate alerts for one indicator (may be several rules)."""
    risk, conf, obs = ind["risk_score"], ind["confidence_score"], ind["observation_count"]
    reasons = []
    if risk >= 70 and conf >= 60:
        reasons.append(("HIGH_RISK_HIGH_CONFIDENCE", "Risk and confidence both exceed thresholds."))
    if obs >= 15:
        reasons.append(("REPEATED_OBSERVATIONS", f"Observed {obs} times."))
    if cluster_size >= 5 and risk >= 55:
        reasons.append(("CORRELATED_INDICATORS", f"Part of a cluster of {cluster_size} related indicators."))
    if ind["type"] == "CVE" and risk >= 60:
        reasons.append(("HIGH_PRIORITY_VULNERABILITY", "Vulnerability indicator with elevated risk."))
    return [{
        "indicator_id": ind["id"], "alert_type": t,
        "severity": classify_risk(risk).title(), "risk_score": risk,
        "confidence_score": conf, "observation_count": obs,
        "description": d, "created_at": ind["last_seen"],
    } for t, d in reasons]


def correlate_alerts(candidates):
    """
    Fight alert fatigue: merge every candidate alert for the same
    indicator into ONE alert that carries an observation count.
    (100 sightings -> 1 alert with observation_count = 100.)
    """
    groups = defaultdict(list)
    for a in candidates:
        groups[a["indicator_id"]].append(a)
    merged = []
    for items in groups.values():
        best = max(items, key=lambda a: SEVERITIES.index(a["severity"]))
        merged.append({
            **best,
            "alert_type": " + ".join(sorted({a["alert_type"] for a in items})),
            "observation_count": max(a["observation_count"] for a in items),
            "merged_events": len(items),
            "description": " ".join(dict.fromkeys(a["description"] for a in items)),
        })
    return merged


EXPOSURE_POINTS = {"Internet-facing": 100, "Internal": 50, "Isolated": 10}
EXPLOIT_POINTS = {"No evidence": 0, "Proof-of-concept (demo)": 60, "Exploited in the wild (demo)": 100}


def calculate_vulnerability_priority(cvss, asset_criticality, exposure, exploitation, patch_available):
    """
    CVSS alone is not enough. Weights: CVSS 35, asset criticality (1-5) 20,
    exposure 20, exploitation evidence 20, no patch available 5.
    """
    score = (0.35 * cvss * 10 + 0.20 * clamp(asset_criticality, 1, 5) * 20
             + 0.20 * EXPOSURE_POINTS.get(exposure, 50)
             + 0.20 * EXPLOIT_POINTS.get(exploitation, 0)
             + 0.05 * (0 if patch_available else 100))
    return int(clamp(round(score)))


def enrich_indicator(conn, pk):
    """Enrich one indicator using LOCAL data only (no internet, no API keys)."""
    ind = conn.execute("SELECT * FROM indicators WHERE id = ?", (pk,)).fetchone()
    if ind is None:
        return None

    related, peers = [], 0
    if ind["campaign_id"]:
        window = ("campaign_id = ? AND id != ? "
                  "AND ABS(julianday(first_seen) - julianday(?)) <= 14")
        args = (ind["campaign_id"], pk, ind["first_seen"])
        peers = conn.execute(f"SELECT COUNT(*) FROM indicators WHERE {window}", args).fetchone()[0]
        related = conn.execute(
            f"SELECT * FROM indicators WHERE {window} ORDER BY risk_score DESC LIMIT 10", args).fetchall()

    alerts = conn.execute("SELECT * FROM alerts WHERE indicator_id = ? ORDER BY id", (pk,)).fetchall()
    notes = conn.execute("""SELECT n.* FROM soc_notes n JOIN alerts a ON a.id = n.alert_id
                            WHERE a.indicator_id = ? ORDER BY n.id DESC""", (pk,)).fetchall()
    cve = None
    if ind["type"] == "CVE":
        cve = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (ind["value"],)).fetchone()

    cluster_size = peers + 1
    record_class = classify_record(
        ind["confidence_score"], ind["risk_score"], cluster_size,
        bool(alerts), any(a["incident"] for a in alerts))

    timeline = [(ind["first_seen"], "First seen")]
    if ind["observation_count"] > 1:
        timeline.append((ind["last_seen"], f"{ind['observation_count']} total observations recorded"))
    for a in alerts:
        timeline.append((a["created_at"], f"Alert raised ({a['alert_type']}), risk {a['risk_score']}"))
        if a["incident"]:
            timeline.append((a["updated_at"], "Analyst declared an incident"))
    timeline.append((ind["last_seen"], f"Last seen. Current status: {ind['status']}"))
    timeline.sort(key=lambda t: t[0] or "")

    return {
        "row": ind, "related": related, "cluster_size": cluster_size, "alerts": alerts,
        "notes": notes, "cve": cve, "record_class": record_class,
        "risk_level": classify_risk(ind["risk_score"]),
        "interpretation": interpret_scores(ind["risk_score"], ind["confidence_score"]),
        "reliability_label": RELIABILITY_LABELS.get(ind["source_reliability"], "Unknown"),
        "actions": RECOMMENDED_ACTIONS.get(ind["category"], []), "timeline": timeline,
    }


# ----- Awareness content -----

# (title, what, why, warning signs, safe practices, what to do if it happens)
AWARENESS_MODULES = [
    ("Phishing Awareness", "Deceptive messages that trick you into clicking, sharing credentials or paying.",
     "Most breaches start with one convincing message.",
     "Urgency, mismatched sender, unexpected attachment or QR code, credential or payment request, impersonation. "
     "Fictional example: 'Mailbox full - sign in at mailbox-verify.example.invalid within 1 hour' (urgency + off-brand link).",
     "Check sender and link destination. Never sign in from a message link. Verify requests through a known channel.",
     "Do not click. Report it. If you clicked, change your password and tell IT immediately."),
    ("Password Security", "Using long, unique passwords or passphrases for each account.",
     "Reused or weak passwords let one breach unlock many accounts.",
     "Same password on many sites, short or guessable passwords, passwords shared in chat.",
     "Use a password manager, long passphrases and a different password per account.",
     "Change the password, check other accounts that reused it, and enable MFA."),
    ("Multi-Factor Authentication (MFA)", "A second proof of identity in addition to your password.",
     "A strong password plus MFA is generally safer than a password alone.",
     "Unexpected approval prompts, requests to read out codes, SMS-only protection on key accounts.",
     "Prefer authenticator apps, passkeys or security keys (WebAuthn, more phishing-resistant than SMS codes).",
     "Deny the prompt, change your password, report possible account targeting."),
    ("Social Engineering", "Manipulating people, not machines, into giving access or information.",
     "Attackers exploit trust, authority and urgency.",
     "Pressure to act now, claimed authority, unusual payment or gift-card requests, tailgating.",
     "Verify identity through an official channel. It is fine to say no or ask for time.",
     "Stop the conversation, report it, and note what was requested."),
    ("Safe Browsing", "Using the web while checking sites and downloads for trust.",
     "Fake and compromised sites steal credentials and deliver unwanted software.",
     "Look-alike domains, certificate warnings, pop-ups demanding downloads.",
     "Type known addresses, download only from official sources, keep the browser updated.",
     "Close the page, do not enter data, run a security scan and report if you entered credentials."),
    ("Secure Wi-Fi", "Connecting to wireless networks safely at home and in public.",
     "Open or fake networks can expose traffic and logins.",
     "Open networks asking for card details, networks named almost like a known venue.",
     "Use WPA2/WPA3, change the router admin password, avoid sensitive logins on public Wi-Fi.",
     "Disconnect, forget the network, change passwords used on it."),
    ("Software Updates", "Installing security patches for systems and apps.",
     "Many attacks rely on known, already-patched weaknesses.",
     "Delayed update prompts, unsupported software, disabled auto-update.",
     "Enable automatic updates and restart when asked.",
     "Update now and tell IT if a system cannot be patched."),
    ("Ransomware Awareness", "Malware that locks files or systems and may threaten data leaks. Defensive overview only.",
     "It causes downtime, data loss and extortion risk.",
     "Unexpected attachments, files suddenly unreadable, ransom notes.",
     "Keep tested offline backups, patch, use least privilege, MFA and email filtering.",
     "Disconnect from the network if instructed, do not pay or negotiate yourself, report immediately."),
    ("USB / Removable Media Safety", "Safe handling of USB drives and external media.",
     "Unknown media can carry malicious files.",
     "Found or gifted drives, unexpected autorun prompts.",
     "Do not plug in unknown media, use approved devices, scan before opening.",
     "Unplug if safe, report to IT, do not retry on other machines."),
    ("Data Privacy", "Sharing and storing personal data responsibly.",
     "Leaked personal data harms people and organizations.",
     "Requests for more data than needed, over-broad app permissions, data sent to wrong recipients.",
     "Share the minimum, review permissions, encrypt and restrict access.",
     "Report misdirected or exposed data using your data-incident process."),
    ("Mobile Security", "Protecting phones and tablets.",
     "Phones hold email, MFA apps and corporate data.",
     "Unknown app links, excessive permissions, outdated OS.",
     "Use a screen lock, install apps from official stores only, keep the OS updated.",
     "Report a lost device at once so it can be locked or wiped."),
    ("Remote Work Security", "Working safely outside the office.",
     "Home networks and personal devices are less controlled.",
     "Shared devices, unpatched routers, screens visible in public.",
     "Use approved devices and VPN, lock the screen, separate work and personal use.",
     "Report suspicious activity and lost equipment."),
    ("Cloud Account Security", "Securing cloud mailboxes, storage and apps.",
     "A single cloud account can expose a lot of data.",
     "Unknown sign-in alerts, public sharing links, unfamiliar app consent requests.",
     "Enforce MFA, review sharing settings, grant minimum permissions.",
     "Revoke suspicious sessions and app access, reset the password, report it."),
    ("Incident Reporting", "Telling the right people quickly when something seems wrong.",
     "Early reports shorten response time and reduce damage.",
     "Strange pop-ups, unexpected sign-in alerts, mis-sent data, clicked suspicious links.",
     "Report early even if unsure. Include what, when and which system. No blame.",
     "Contact IT/security through the official channel and follow their guidance."),
    ("AI-Enabled Scam Awareness", "Scams using AI-generated text, voices or images to impersonate others.",
     "Messages and voices can look and sound convincing.",
     "Urgent requests with unusual payment methods, voice or video that cannot be verified, perfect but generic wording.",
     "Verify by calling back a known number, agree on verification steps for payments.",
     "Pause, verify independently, and report the attempt."),
]
MODULE_TITLES = {m[0] for m in AWARENESS_MODULES}

CATEGORY_TO_MODULE = {
    "Phishing": "Phishing Awareness", "Passwords": "Password Security",
    "MFA": "Multi-Factor Authentication (MFA)", "Social Engineering": "Social Engineering",
    "Safe Browsing": "Safe Browsing", "Ransomware": "Ransomware Awareness",
    "Privacy": "Data Privacy", "Wi-Fi": "Secure Wi-Fi",
    "Mobile Security": "Mobile Security", "Incident Reporting": "Incident Reporting",
}

# (category, question, options, correct index, explanation)
QUIZ = [
    ("Phishing", "An email from 'IT Support' urgently asks you to verify your password through a link. What should you do?",
     ["Click the link and sign in quickly", "Reply with your password", "Verify through an official channel you already know", "Forward it to colleagues"],
     2, "Urgency plus a credential request is a classic phishing sign. Verify through a trusted channel."),
    ("Phishing", "Which is a common phishing warning sign?",
     ["A message from a known contact about a meeting you set up", "A mismatched sender domain with an unexpected attachment", "A newsletter you subscribed to", "A calendar invite you were expecting"],
     1, "Mismatched senders and unexpected attachments are typical red flags."),
    ("Phishing", "An email contains an unexpected QR code asking you to log in. What is the best action?",
     ["Scan it right away", "Scan it with a personal phone", "Do not scan; verify through an official channel and report it", "Reply asking if it is safe"],
     2, "QR codes hide the destination. Verify independently and report."),
    ("Passwords", "Which is the strongest password approach?",
     ["Summer2024!", "A long unique passphrase kept in a password manager", "Your pet's name plus 123", "One strong password for everything"],
     1, "Long, unique passphrases managed by a password manager are best."),
    ("Passwords", "Why is reusing passwords risky?",
     ["Passwords expire faster", "One breach can expose every account that shares it", "It slows down login", "It disables MFA"],
     1, "Attackers try leaked passwords on other sites."),
    ("Passwords", "A password manager helps because it...",
     ["Shares passwords with coworkers", "Generates and stores unique passwords", "Removes the need for MFA", "Makes weak passwords strong"],
     1, "It makes unique, strong passwords practical."),
    ("MFA", "What does MFA add to a login?",
     ["A second proof of identity beyond the password", "A longer password", "Automatic virus scanning", "Faster sign-in"],
     0, "MFA requires an additional factor, so a stolen password alone is not enough."),
    ("MFA", "You receive an MFA approval prompt you did not request. What should you do?",
     ["Approve it to stop the prompts", "Deny it, change your password and report it", "Ignore it and keep working", "Read the code to support"],
     1, "Unexpected prompts can mean your password is compromised."),
    ("MFA", "Which sign-in method is generally most resistant to phishing?",
     ["SMS codes", "Passkeys or security keys (WebAuthn)", "Email codes", "Security questions"],
     1, "Passkeys and security keys are bound to the real site."),
    ("Social Engineering", "A caller claiming to be from the CEO's office demands an urgent gift-card purchase. Best response?",
     ["Comply quickly", "Verify through a known official contact before acting", "Send the codes by text", "Give your employee ID"],
     1, "Authority plus urgency is a manipulation pattern. Verify first."),
    ("Social Engineering", "Which tactic is common in social engineering?",
     ["Creating urgency or authority pressure", "Publishing patch notes", "Posting a privacy policy", "Enabling MFA"],
     0, "Pressure bypasses careful thinking."),
    ("Social Engineering", "A stranger asks you to hold a secure door open for them. What should you do?",
     ["Hold the door", "Politely ask them to badge in or contact security", "Lend them your badge", "Ignore them"],
     1, "Tailgating defeats physical access controls."),
    ("Safe Browsing", "Before entering credentials on a website, you should check...",
     ["The page's color scheme", "That the address is exactly the domain you expect", "The number of ads", "Page speed"],
     1, "Look-alike domains are common."),
    ("Safe Browsing", "Your browser warns about an invalid certificate on a login page. You should...",
     ["Proceed anyway", "Stop and verify the site through official channels", "Disable the warning", "Share the link"],
     1, "Certificate warnings can indicate impersonation or interception."),
    ("Safe Browsing", "Software is safest to download from...",
     ["Any search result", "The vendor's official site or a trusted store", "Pop-up ads", "Links in chat"],
     1, "Unofficial sources often bundle unwanted software."),
    ("Ransomware", "What is the best protection against data loss from ransomware?",
     ["Regular, tested offline backups", "Paying quickly", "Disabling updates", "Ignoring warnings"],
     0, "Good backups allow recovery without negotiating."),
    ("Ransomware", "You suspect ransomware on your computer. What first?",
     ["Keep working", "Follow instructions to disconnect and report to IT immediately", "Delete files", "Pay the ransom"],
     1, "Fast reporting limits spread."),
    ("Ransomware", "Which practice reduces ransomware risk?",
     ["Timely patching and least privilege", "Using admin accounts daily", "Opening all attachments", "Sharing passwords"],
     0, "Patching and limited privileges reduce attack paths."),
    ("Privacy", "Sharing personal data online should follow which principle?",
     ["Share everything for convenience", "Data minimization: share only what is needed", "Post it publicly", "Reuse it everywhere"],
     1, "Less shared data means less exposed data."),
    ("Privacy", "You notice a file with customer data was emailed to the wrong person. What next?",
     ["Ignore it", "Report it promptly through the data-incident process", "Delete the evidence", "Post an apology publicly"],
     1, "Prompt reporting enables correct handling."),
    ("Privacy", "How should app permissions be handled?",
     ["Accept all", "Review them and allow only what the app needs", "Grant everything to unknown apps", "Never look at them"],
     1, "Over-broad permissions expose data."),
    ("Wi-Fi", "On public Wi-Fi, a safer practice is to...",
     ["Do banking without protection", "Avoid sensitive logins or use mobile data / a trusted VPN", "Turn off updates", "Share your credentials"],
     1, "Public networks are less trustworthy."),
    ("Wi-Fi", "Which describes a safer home router setup?",
     ["Keep the default admin password", "Change the admin password, use WPA2/WPA3 and apply updates", "Use no password", "Use WEP"],
     1, "Default credentials and old protocols are easy to abuse."),
    ("Wi-Fi", "A 'free cafe Wi-Fi' asks for your card details to connect. This is...",
     ["Normal", "A warning sign; do not enter details", "Required", "Safe because it is free"],
     1, "Legitimate Wi-Fi sign-ins do not need card numbers."),
    ("Mobile Security", "Which keeps a mobile device more secure?",
     ["Skipping updates", "A screen lock and installing OS updates", "Rooting the device", "Installing apps from links"],
     1, "Locks and updates are baseline protections."),
    ("Mobile Security", "Your work phone is lost. What should you do?",
     ["Ignore it", "Report it immediately so it can be locked or wiped", "Ask in public chats", "Wait a week"],
     1, "Fast reporting protects the data on it."),
    ("Mobile Security", "Which is a safe app source?",
     ["The official app store, checking permissions", "Unknown APK links", "A random SMS link", "A forum attachment"],
     0, "Official stores perform checks."),
    ("Incident Reporting", "When should you report a suspected security incident?",
     ["Only when certain", "As soon as you notice, even if unsure", "After a week", "Never"],
     1, "Early reports shorten response time."),
    ("Incident Reporting", "A good incident report includes...",
     ["What you saw, when, and which systems were involved", "Only your opinion", "Nothing", "Your passwords"],
     0, "Facts help the responders. Never include passwords."),
    ("Incident Reporting", "You clicked a suspicious link by mistake. Best action?",
     ["Hide it", "Report it quickly and follow IT's guidance", "Wait and see", "Clean up quietly"],
     1, "Quick reporting beats silence."),
]


def score_quiz(answers):
    """answers: {question_index: chosen_option_index}. Educational score only."""
    per = defaultdict(lambda: [0, 0])
    for i, (cat, _q, _o, correct, _e) in enumerate(QUIZ):
        per[cat][1] += 1
        if answers.get(i) == correct:
            per[cat][0] += 1
    category_scores = {c: round(100 * r / t) for c, (r, t) in per.items()}
    right = sum(v[0] for v in per.values())
    overall = round(100 * right / len(QUIZ))
    return {"overall": overall, "band": awareness_band(overall), "categories": category_scores,
            "weakest": sorted((c for c, s in category_scores.items() if s < 60), key=category_scores.get),
            "recommendations": generate_learning_recommendations(category_scores)}


def awareness_band(score):
    if score <= 40:
        return "Needs Improvement"
    if score <= 60:
        return "Basic Awareness"
    if score <= 80:
        return "Good Awareness"
    return "Strong Awareness"


def generate_learning_recommendations(category_scores):
    out = []
    for cat, pct in sorted(category_scores.items(), key=lambda kv: kv[1]):
        module = CATEGORY_TO_MODULE.get(cat, cat)
        if pct >= 80:
            out.append({"category": cat, "score": pct, "text": "No immediate module required."})
        elif pct >= 60:
            out.append({"category": cat, "score": pct, "text": f"Optional refresher: {module}."})
        else:
            out.append({"category": cat, "score": pct, "text": f"Review the module: {module}."})
    return out


# ============================================================
# 4. DATABASE
# ============================================================

def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def columns(conn, table):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def init_db():
    """Create tables. Older schemas are rebuilt (users and audit logs are kept)."""
    conn = connect_db()
    if conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
        for table in ("soc_notes", "alerts", "indicators", "cves", "quiz_results"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")

    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer', created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, action TEXT NOT NULL,
        details TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT UNIQUE, threat_name TEXT,
        category TEXT, type TEXT, value TEXT, source TEXT, source_reliability TEXT,
        severity TEXT, confidence_score INTEGER, risk_score INTEGER,
        observation_count INTEGER DEFAULT 1, campaign_id TEXT, status TEXT DEFAULT 'NEW',
        first_seen TEXT, last_seen TEXT, mitre_tactic TEXT, mitre_id TEXT,
        mitre_technique TEXT, cve_id TEXT, description TEXT);
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_id INTEGER REFERENCES indicators(id) ON DELETE CASCADE,
        alert_type TEXT, title TEXT, severity TEXT, risk_score INTEGER, confidence_score INTEGER,
        observation_count INTEGER DEFAULT 1, merged_events INTEGER DEFAULT 1, description TEXT,
        status TEXT DEFAULT 'NEW', incident INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS soc_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
        author TEXT, note TEXT, created_at TEXT);
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT UNIQUE, product_category TEXT,
        description TEXT, severity TEXT, cvss REAL, published_date TEXT, patch_available INTEGER,
        exploitation_status_demo TEXT, asset_criticality INTEGER, exposure TEXT, priority_score INTEGER);
    CREATE TABLE IF NOT EXISTS quiz_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT, anon_id TEXT, overall_score INTEGER,
        category_scores TEXT, created_at TEXT);
    CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators(value);
    CREATE INDEX IF NOT EXISTS idx_ind_sev ON indicators(severity);
    CREATE INDEX IF NOT EXISTS idx_ind_cat ON indicators(category);
    CREATE INDEX IF NOT EXISTS idx_ind_camp ON indicators(campaign_id);
    CREATE INDEX IF NOT EXISTS idx_ind_status ON indicators(status);
    CREATE INDEX IF NOT EXISTS idx_alert_ind ON alerts(indicator_id);
    CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
    """)

    if "role" not in columns(conn, "users"):      # users from the older version
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'")
        conn.execute("UPDATE users SET role = 'admin'")
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    if conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 0:
        seed_cves(conn)
    if conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 0:
        seed_threats(conn)
    conn.commit()
    conn.close()


def seed_cves(conn):
    """Fictional vulnerabilities (CVE-2099-xxxx). Not real CVE records."""
    rng = random.Random(7)
    products = ["Web server", "Operating system", "Browser", "VPN appliance", "Database",
                "Email platform", "Cloud service", "IoT device"]
    # Two hand-made rows show why CVSS alone is not enough.
    fixed = {
        1: (9.8, 1, "Isolated", "No evidence", 1, "Operating system"),
        2: (7.8, 5, "Internet-facing", "Exploited in the wild (demo)", 0, "VPN appliance"),
    }
    now = datetime.now()
    for n, cid in enumerate(DEMO_CVE_IDS, 1):
        if n in fixed:
            cvss, crit, exposure, exploit, patch, product = fixed[n]
        else:
            cvss = round(rng.uniform(3.0, 9.9), 1)
            crit, exposure = rng.randint(1, 5), rng.choice(list(EXPOSURE_POINTS))
            exploit, patch = rng.choice(list(EXPLOIT_POINTS)), rng.choice([0, 1, 1])
            product = rng.choice(products)
        severity = ("Critical" if cvss >= 9 else "High" if cvss >= 7 else "Medium" if cvss >= 4 else "Low")
        conn.execute("""INSERT INTO cves (cve_id, product_category, description, severity, cvss,
            published_date, patch_available, exploitation_status_demo, asset_criticality, exposure,
            priority_score) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                     (cid, product, f"SYNTHETIC / DEMO ONLY. Fictional weakness in a {product.lower()}.",
                      severity, cvss, (now - timedelta(days=rng.randint(5, 300))).date().isoformat(),
                      patch, exploit, crit, exposure,
                      calculate_vulnerability_priority(cvss, crit, exposure, exploit, patch)))


def make_value(kind, i, rng):
    if kind == "IP":      # reserved documentation ranges only
        return f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(1, 254)}"
    if kind == "Domain":
        return f"sample-{i}.{rng.choice(['example.com', 'example.org', 'example.net', 'invalid'])}"
    if kind == "URL":
        return f"https://sample-{i}.example.net/{rng.choice(['login', 'verify', 'update', 'download'])}"
    if kind == "Hash":    # random SHA-256-style string: SYNTHETIC / DEMO ONLY
        return f"{rng.getrandbits(256):064x}"
    if kind == "Email Domain":
        return f"mail-{i}.example.org"
    return rng.choice(DEMO_CVE_IDS)


def seed_threats(conn):
    """2,000 synthetic threat records + alerts. Reproducible (seeded RNG)."""
    rng = random.Random(42)
    now = datetime.now()
    campaigns = [{"id": f"CMP-{n + 1:03d}", "category": CATEGORIES[n % len(CATEGORIES)],
                  "start": now - timedelta(days=rng.randint(8, 85))} for n in range(150)]
    sources = list(SOURCES)

    recs = []
    # --- Safe demonstration scenario THR-2026-001 (never visited or contacted) ---
    demo_hash = hashlib.sha256(b"synthetic-demo-phishing-kit").hexdigest()
    for kind, value, obs, conf in (("Domain", "login-check.invalid", 8, 85), ("IP", "198.51.100.25", 6, 80),
                                   ("URL", "https://login-check.invalid/verify", 5, None), ("Hash", demo_hash, 3, None)):
        recs.append({"type": kind, "value": value, "category": "Phishing", "campaign_id": "CMP-DEMO",
                     "source": "Security Vendor", "severity": "High", "obs": obs, "status": "MONITORING",
                     "first": now - timedelta(days=6), "last": now - timedelta(days=1),
                     "conf_override": conf, "name": "Synthetic Credential Phishing Campaign"})

    for i in range(2000):
        camp = rng.choice(campaigns) if rng.random() < 0.75 else None     # 25% stand-alone
        category = camp["category"] if camp else rng.choice(CATEGORIES)
        kind = rng.choice(TYPE_BY_CATEGORY[category])
        start = camp["start"] if camp else now - timedelta(days=rng.randint(2, 88))
        first = min(start + timedelta(hours=rng.randint(0, 480)), now - timedelta(hours=2))
        last = min(now, first + timedelta(hours=rng.randint(1, 600)))
        recs.append({
            "type": kind, "value": make_value(kind, i, rng), "category": category,
            "campaign_id": camp["id"] if camp else None, "source": rng.choice(sources),
            "severity": rng.choices(SEVERITIES, weights=[10, 25, 30, 22, 13])[0],
            "obs": rng.choice([1, 1, 2, 3, 5, 8, 12, 18, 25, 40]),
            "status": rng.choices(IND_STATUSES, weights=[30, 20, 20, 20, 10])[0],
            "first": first, "last": last, "conf_override": None,
            "name": (f"Synthetic {category} Campaign {camp['id']}" if camp else f"Synthetic {category} Observation")})

    camp_sources, camp_high = defaultdict(set), Counter()
    for r in recs:
        if r["campaign_id"]:
            camp_sources[r["campaign_id"]].add(r["source"])
            camp_high[r["campaign_id"]] += r["severity"] in ("High", "Critical")

    for n, r in enumerate(recs):
        reliability = SOURCES[r["source"]]
        age = (now - r["last"]).days
        corroboration = max(0, len(camp_sources.get(r["campaign_id"], ())) - 1)
        conf = r["conf_override"] or calculate_confidence(reliability, r["obs"], age, corroboration)
        peers = max(0, camp_high.get(r["campaign_id"], 0) - (r["severity"] in ("High", "Critical")))
        risk = calculate_threat_risk(r["severity"], conf, r["last"].isoformat(timespec="seconds"),
                                     r["obs"], reliability, peers, now)
        mapping = (None, None, None)
        if conf >= 50 and r["campaign_id"] and r["category"] in CATEGORY_ATTACK:   # context justifies it
            mapping = CATEGORY_ATTACK[r["category"]]
        conn.execute("""INSERT INTO indicators (threat_id, threat_name, category, type, value, source,
            source_reliability, severity, confidence_score, risk_score, observation_count, campaign_id,
            status, first_seen, last_seen, mitre_tactic, mitre_id, mitre_technique, cve_id, description)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            "THR-2026-001" if n == 0 else f"THR-2026-{1000 + n}", r["name"], r["category"], r["type"],
            r["value"], r["source"], reliability, r["severity"], conf, risk, r["obs"], r["campaign_id"],
            r["status"], r["first"].isoformat(timespec="seconds"), r["last"].isoformat(timespec="seconds"),
            mapping[0], mapping[1], mapping[2], r["value"] if r["type"] == "CVE" else None,
            f"SYNTHETIC / DEMO ONLY. Fictional {r['type']} indicator for simulated "
            f"{r['category'].lower()} activity. Never visit or execute."))

    # --- alerts: generate candidates, then correlate to avoid alert fatigue ---
    rows = conn.execute("SELECT * FROM indicators").fetchall()
    size_of = {m: c["size"] for c in correlate_threats(rows) for m in c["member_ids"]}
    value_of = {r["id"]: r["value"] for r in rows}
    candidates = []
    for r in rows:
        if r["status"] not in ("CLOSED", "FALSE_POSITIVE"):
            candidates += generate_threat_alert(r, size_of.get(r["id"], 1))
    for a in correlate_alerts(candidates):
        status = ("MONITORING" if a["indicator_id"] <= 4 else
                  rng.choices(ALERT_STATUSES, weights=[50, 20, 15, 10, 5])[0])
        conn.execute("""INSERT INTO alerts (indicator_id, alert_type, title, severity, risk_score,
            confidence_score, observation_count, merged_events, description, status, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
            a["indicator_id"], a["alert_type"], f"{value_of[a['indicator_id']][:60]} - "
            f"{a['alert_type'].split(' + ')[0].replace('_', ' ').title()}", a["severity"], a["risk_score"],
            a["confidence_score"], a["observation_count"], a["merged_events"], a["description"], status,
            a["created_at"], a["created_at"]))

    demo_alert = conn.execute("SELECT id FROM alerts WHERE indicator_id = 1").fetchone()
    if demo_alert:
        conn.execute("INSERT INTO soc_notes (alert_id, author, note, created_at) VALUES (?,?,?,?)",
                     (demo_alert["id"], "system",
                      "Indicator appears in multiple synthetic phishing observations. Do not visit the domain.",
                      now.isoformat(timespec="seconds")))


# ============================================================
# 5. AUTHENTICATION, ROLES, AUDIT LOG
# ============================================================

class User(UserMixin):
    def __init__(self, user_id, username, role):
        self.id, self.username, self.role = str(user_id), username, role


@login_manager.user_loader
def load_user(user_id):
    conn = connect_db()
    row = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return User(row["id"], row["username"], row["role"]) if row else None


def log_activity(action, details="", username=None):
    if username is None:
        if not current_user.is_authenticated:
            return
        username = current_user.username
    conn = connect_db()
    try:
        conn.execute("INSERT INTO audit_logs (username, action, details, created_at) VALUES (?,?,?,?)",
                     (username, action, str(details)[:1000], datetime.now().isoformat(timespec="seconds")))
        conn.commit()
    finally:
        conn.close()


def roles_required(*roles):
    """RBAC: viewer (read only), analyst (triage), admin (everything)."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if getattr(current_user, "role", None) not in roles:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Forbidden"}), 403
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


FAILED_LOGINS = defaultdict(list)     # in-memory throttle (demo-grade)
MAX_FAILS, LOCK_SECONDS = 5, 600


def login_locked(key):
    FAILED_LOGINS[key] = [t for t in FAILED_LOGINS[key] if time.time() - t < LOCK_SECONDS]
    return len(FAILED_LOGINS[key]) >= MAX_FAILS


@app.before_request
def require_login():
    if request.endpoint in ("login", "static") or request.endpoint is None:
        return None
    if not current_user.is_authenticated:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("login", next=request.path))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = f"{request.remote_addr}|{username.lower()}"
        if login_locked(key):
            log_activity("LOGIN_BLOCKED", "Too many failed attempts", username=username or "unknown")
            error = "Too many failed attempts. Try again in 10 minutes."
        else:
            conn = connect_db()
            user = conn.execute("SELECT id, username, role, password_hash FROM users WHERE username = ?",
                                (username,)).fetchone()
            conn.close()
            if user and check_password_hash(user["password_hash"], password):
                FAILED_LOGINS.pop(key, None)
                login_user(User(user["id"], user["username"], user["role"]), remember=False, fresh=True)
                log_activity("LOGIN", "Successful login", username=user["username"])
                nxt = request.args.get("next", "")
                if nxt.startswith("/") and not nxt.startswith("//"):
                    return redirect(nxt)
                return redirect(url_for("dashboard"))
            FAILED_LOGINS[key].append(time.time())
            log_activity("LOGIN_FAILED", "Invalid credentials", username=username[:80] or "unknown")
            error = "Invalid username or password."

    return render_template_string("""
    <!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login | Threat Intelligence Dashboard</title>
    <style>
      body{margin:0;background:#101827;color:#e5e7eb;font-family:Arial,sans-serif;display:grid;min-height:100vh;place-items:center}
      .box{width:min(90%,380px);background:#1e293b;padding:28px;border-radius:12px;border:1px solid #334155}
      input{display:block;box-sizing:border-box;width:100%;padding:11px;margin:8px 0 16px;border-radius:6px;border:1px solid #64748b}
      button{width:100%;padding:11px;background:#2563eb;color:#fff;border:0;border-radius:6px;cursor:pointer}
      .error{color:#f87171}.muted{color:#94a3b8}
    </style></head><body><div class="box">
      <h1>Dashboard Login</h1><p class="muted">Educational, defensive project. Synthetic data only.</p>
      {% if error %}<p class="error">{{ error }}</p>{% endif %}
      <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <label for="username">Username</label><input id="username" name="username" autocomplete="username" required>
        <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Log in</button></form></div></body></html>""", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    log_activity("LOGOUT", "User logged out")
    logout_user()
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(e):
    return page("Access denied", "<div class='card'>Your role does not allow this action.</div>"), 403


@app.errorhandler(404)
def not_found(e):
    return page("Not found", "<div class='card'>That page or record does not exist.</div>"), 404


@app.errorhandler(400)
def bad_request(e):
    return page("Bad request", "<div class='card'>{{ msg }}</div>", msg=getattr(e, "description", "Bad request")), 400


# ============================================================
# 6. PAGE LAYOUT
# ============================================================

LAYOUT_HEAD = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
 *{box-sizing:border-box} body{margin:0;font-family:Arial,sans-serif;background:#101827;color:#e5e7eb}
 nav{background:#172235;padding:14px 22px;display:flex;align-items:center;flex-wrap:wrap;gap:14px}
 nav a{color:#93c5fd;text-decoration:none;font-size:14px} nav a:hover{text-decoration:underline}
 nav form{margin-left:auto} main{max-width:1250px;margin:24px auto;padding:0 20px}
 h1,h2,h3{color:#f8fafc} .card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:18px;margin-bottom:18px}
 .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:18px}
 .cards .card{margin:0} .metric{font-size:28px;font-weight:bold;margin:0}
 .grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:16px}
 .grid2 .card{margin:0} table{width:100%;border-collapse:collapse;margin-top:10px;font-size:14px}
 th,td{padding:9px;text-align:left;border-bottom:1px solid #334155;overflow-wrap:anywhere}
 th{background:#263449} input,select,textarea,button{padding:9px;margin:4px;border-radius:5px;border:1px solid #64748b;font:inherit}
 button,.button{background:#2563eb;color:#fff;cursor:pointer;border:0;text-decoration:none;display:inline-block;padding:9px 12px;border-radius:5px}
 a{color:#93c5fd} .notice{background:#422006;padding:12px;border-radius:6px;color:#fde68a;margin-bottom:18px}
 .wrap{overflow-x:auto} .muted{color:#94a3b8} .bar{display:grid;grid-template-columns:130px 1fr 44px;gap:8px;align-items:center;margin:6px 0;font-size:13px}
 .track{background:#0f172a;border-radius:4px;height:14px} .fill{background:#3b82f6;height:14px;border-radius:4px}
 .badge{padding:2px 8px;border-radius:10px;font-size:12px;background:#334155}
 .critical{background:#991b1b}.high{background:#c2410c}.medium{background:#a16207}.low{background:#166534}.informational{background:#475569}
 details{background:#0f172a;border-radius:8px;padding:10px;margin:8px 0} summary{cursor:pointer;font-weight:bold}
 .ok{color:#86efac}.bad{color:#fca5a5}
</style></head><body>
<nav>
 <a href="{{ url_for('dashboard') }}">Dashboard</a><a href="{{ url_for('ioc_search') }}">IOC Search</a>
 <a href="{{ url_for('alerts_page') }}">Alerts</a><a href="{{ url_for('soc_dashboard') }}">SOC</a>
 <a href="{{ url_for('correlation_page') }}">Correlation</a><a href="{{ url_for('attack_page') }}">ATT&amp;CK</a>
 <a href="{{ url_for('cve_page') }}">Vulnerabilities</a><a href="{{ url_for('awareness_page') }}">Awareness</a>
 <a href="{{ url_for('quiz_page') }}">Quiz</a><a href="{{ url_for('executive_page') }}">Executive</a>
 <a href="{{ url_for('ir_guide') }}">IR Guide</a>
 {% if current_user.role == 'admin' %}<a href="{{ url_for('audit_page') }}">Audit</a>{% endif %}
 <form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <span class="muted">{{ current_user.username }} ({{ current_user.role }})</span><button type="submit">Logout</button></form>
</nav>
{% macro bars(title, items) %}
<div class="card"><h3>{{ title }}</h3>
 {% set top = (items|map(attribute=1)|max) or 1 %}
 {% for label, value in items %}
  <div class="bar"><span>{{ label }}</span><div class="track"><div class="fill" style="width: {{ (value / top * 100)|round|int }}%"></div></div><b>{{ value }}</b></div>
 {% else %}<p class="muted">No data.</p>{% endfor %}
</div>{% endmacro %}
{% macro sev(s) %}<span class="badge {{ (s or '')|lower }}">{{ s or 'N/A' }}</span>{% endmacro %}
<main><h1>{{ title }}</h1>
<div class="notice">Educational dashboard. All indicators, scores, correlations and CVE examples are SYNTHETIC. Nothing here is contacted or executed.</div>
"""


def page(title, body, **context):
    return render_template_string(LAYOUT_HEAD + body + "</main></body></html>", title=title, **context)


def pairs(rows):
    return [(r[0], r[1]) for r in rows]


def ordered(rows, order):
    d = dict(pairs(rows))
    return [(k, d.get(k, 0)) for k in order]


def bucket_chart(conn, column):
    sql = f"""SELECT CASE WHEN {column} <= 20 THEN '0-20' WHEN {column} <= 40 THEN '21-40'
              WHEN {column} <= 60 THEN '41-60' WHEN {column} <= 80 THEN '61-80' ELSE '81-100' END AS b,
              COUNT(*) FROM indicators GROUP BY b"""
    return ordered(conn.execute(sql).fetchall(), ["0-20", "21-40", "41-60", "61-80", "81-100"])


# ============================================================
# 7. PAGES
# ============================================================

def dashboard_stats(conn):
    one = lambda sql: conn.execute(sql).fetchone()[0]
    return {
        "total_threat_records": one("SELECT COUNT(*) FROM indicators"),
        "critical_threats": one("SELECT COUNT(*) FROM indicators WHERE severity='Critical'"),
        "high_threats": one("SELECT COUNT(*) FROM indicators WHERE severity='High'"),
        "active_indicators": one("SELECT COUNT(*) FROM indicators WHERE status IN ('NEW','UNDER_REVIEW','MONITORING')"),
        "open_investigations": one("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')"),
        "average_confidence": round(one("SELECT COALESCE(AVG(confidence_score),0) FROM indicators"), 1),
        "vulnerabilities_tracked": one("SELECT COUNT(*) FROM cves"),
        "total_alerts": one("SELECT COUNT(*) FROM alerts"),
    }


SORTS = {"newest": "first_seen DESC", "risk": "risk_score DESC",
         "confidence": "confidence_score DESC", "observed": "observation_count DESC"}
PER_PAGE = 50


def paginate(total, page_no):
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return min(max(1, page_no), pages), pages


@app.route("/")
def dashboard():
    conn = connect_db()
    try:
        a = request.args
        cond, params = [], []
        for col, allowed in (("severity", SEVERITIES), ("category", CATEGORIES),
                             ("type", TYPES), ("status", IND_STATUSES)):
            if a.get(col, "") in allowed:
                cond.append(f"{col} = ?")
                params.append(a[col])
        for key, col in (("min_risk", "risk_score"), ("min_conf", "confidence_score")):
            val = a.get(key, type=int)
            if val is not None:
                cond.append(f"{col} >= ?")
                params.append(val)
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", a.get("date_from", "")):
            cond.append("first_seen >= ?")
            params.append(a["date_from"])
        search = a.get("q", "").strip()[:100]
        if search:
            cond.append("(value LIKE ? OR threat_name LIKE ? OR threat_id LIKE ?)")
            params += [f"%{search}%"] * 3
        where = ("WHERE " + " AND ".join(cond)) if cond else ""
        sort = a.get("sort", "newest") if a.get("sort") in SORTS else "newest"

        total = conn.execute(f"SELECT COUNT(*) FROM indicators {where}", params).fetchone()[0]
        page_no, pages = paginate(total, a.get("page", 1, type=int) or 1)
        rows = conn.execute(
            f"""SELECT id, threat_id, threat_name, category, type, value, severity, risk_score,
                confidence_score, observation_count, first_seen, last_seen, status FROM indicators
                {where} ORDER BY {SORTS[sort]}, id DESC LIMIT ? OFFSET ?""",
            params + [PER_PAGE, (page_no - 1) * PER_PAGE]).fetchall()

        charts = {
            "time": pairs(conn.execute(
                "SELECT strftime('%Y-%m-%d', first_seen, 'weekday 0', '-6 days') AS wk, COUNT(*) "
                "FROM indicators GROUP BY wk ORDER BY wk").fetchall()),
            "severity": ordered(conn.execute("SELECT severity, COUNT(*) FROM indicators GROUP BY 1").fetchall(), SEVERITIES),
            "category": pairs(conn.execute("SELECT category, COUNT(*) c FROM indicators GROUP BY 1 ORDER BY c DESC").fetchall()),
            "type": pairs(conn.execute("SELECT type, COUNT(*) c FROM indicators GROUP BY 1 ORDER BY c DESC").fetchall()),
            "tactic": pairs(conn.execute("SELECT mitre_tactic, COUNT(*) c FROM indicators WHERE mitre_tactic IS NOT NULL "
                                         "GROUP BY 1 ORDER BY c DESC LIMIT 8").fetchall()),
            "risk": bucket_chart(conn, "risk_score"),
            "conf": bucket_chart(conn, "confidence_score"),
            "status": ordered(conn.execute("SELECT status, COUNT(*) FROM indicators GROUP BY 1").fetchall(), IND_STATUSES),
            "vuln": ordered(conn.execute("SELECT severity, COUNT(*) FROM cves GROUP BY 1").fetchall(), SEVERITIES),
        }
        stats = dashboard_stats(conn)
    finally:
        conn.close()

    qs = urlencode({k: v for k, v in a.items() if k != "page" and v})
    body = """
    <div class="cards">
      {% for label, key in [('Total threat records','total_threat_records'),('Critical threats','critical_threats'),
        ('High threats','high_threats'),('Active indicators','active_indicators'),
        ('Open investigations','open_investigations'),('Average confidence','average_confidence'),
        ('Vulnerabilities tracked','vulnerabilities_tracked')] %}
        <div class="card"><p class="metric">{{ stats[key] }}</p>{{ label }}</div>
      {% endfor %}
    </div>
    <div class="card"><b>Reading this dashboard:</b> an <i>observation</i> is a raw sighting, an <i>indicator</i> is a tracked IOC,
      an <i>alert</i> asks an analyst to triage, a <i>threat</i> is an alerted, corroborated cluster, and an <i>incident</i> is only
      declared by an analyst. <b>High risk does not mean confirmed compromise.</b></div>
    <div class="grid2">
      {{ bars('Threats over time (weekly)', charts.time) }}{{ bars('Threats by severity', charts.severity) }}
      {{ bars('Threats by category', charts.category) }}{{ bars('IOC type distribution', charts.type) }}
      {{ bars('Top ATT&CK tactics (mapped records only)', charts.tactic) }}{{ bars('Risk score distribution', charts.risk) }}
      {{ bars('Confidence distribution', charts.conf) }}{{ bars('Threat status distribution', charts.status) }}
      {{ bars('Vulnerabilities by severity', charts.vuln) }}
    </div>
    <div class="card" style="margin-top:18px"><h2>Threat records</h2>
     <form method="get">
      <input name="q" placeholder="Search indicator, name or ID" value="{{ request.args.get('q','') }}">
      <select name="severity"><option value="">Severity</option>{% for s in severities %}<option {{ 'selected' if request.args.get('severity')==s }}>{{ s }}</option>{% endfor %}</select>
      <select name="category"><option value="">Category</option>{% for s in categories %}<option {{ 'selected' if request.args.get('category')==s }}>{{ s }}</option>{% endfor %}</select>
      <select name="type"><option value="">Type</option>{% for s in types %}<option {{ 'selected' if request.args.get('type')==s }}>{{ s }}</option>{% endfor %}</select>
      <select name="status"><option value="">Status</option>{% for s in statuses %}<option {{ 'selected' if request.args.get('status')==s }}>{{ s }}</option>{% endfor %}</select>
      <input name="min_risk" type="number" min="0" max="100" placeholder="Min risk" style="width:90px" value="{{ request.args.get('min_risk','') }}">
      <input name="min_conf" type="number" min="0" max="100" placeholder="Min conf." style="width:90px" value="{{ request.args.get('min_conf','') }}">
      <input name="date_from" type="date" value="{{ request.args.get('date_from','') }}">
      <select name="sort">{% for k, label in [('newest','Newest'),('risk','Highest risk'),('confidence','Highest confidence'),('observed','Most observed')] %}
        <option value="{{ k }}" {{ 'selected' if sort==k }}>{{ label }}</option>{% endfor %}</select>
      <button type="submit">Apply</button> <a class="button" href="{{ url_for('dashboard') }}">Clear</a>
     </form>
     <p class="muted">{{ total }} matching records. Page {{ page_no }} of {{ pages }}.</p>
     <div class="wrap"><table>
      <tr><th>Threat ID</th><th>Name</th><th>Category</th><th>Indicator</th><th>Severity</th><th>Risk</th>
          <th>Conf.</th><th>Seen</th><th>First seen</th><th>Last seen</th><th>Status</th><th></th></tr>
      {% for r in rows %}
      <tr><td>{{ r.threat_id }}</td><td>{{ r.threat_name }}</td><td>{{ r.category }}</td>
          <td>{{ r.type }}: {{ r.value }}</td><td>{{ sev(r.severity) }}</td><td>{{ r.risk_score }}</td>
          <td>{{ r.confidence_score }}%</td><td>{{ r.observation_count }}</td><td>{{ r.first_seen[:10] }}</td>
          <td>{{ r.last_seen[:10] }}</td><td>{{ r.status }}</td>
          <td><a href="{{ url_for('threat_detail', threat_pk=r.id) }}">View</a></td></tr>
      {% else %}<tr><td colspan="12">No matching records.</td></tr>{% endfor %}
     </table></div>
     <p>{% if page_no > 1 %}<a href="?{{ qs }}&page={{ page_no - 1 }}">&larr; Previous</a>{% endif %}
        {% if page_no < pages %} <a href="?{{ qs }}&page={{ page_no + 1 }}">Next &rarr;</a>{% endif %}</p>
    </div>"""
    return page("Threat Intelligence Dashboard", body, stats=stats, charts=charts, rows=rows, total=total,
                page_no=page_no, pages=pages, qs=qs, sort=sort, severities=SEVERITIES, categories=CATEGORIES,
                types=TYPES, statuses=IND_STATUSES)


def lookup_indicator(conn, value):
    """Validate, then query the LOCAL database only. Never connects to the indicator."""
    result = validate_indicator(value)
    matches = []
    if result["valid"]:
        matches = conn.execute("SELECT * FROM indicators WHERE LOWER(value) = LOWER(?) "
                               "ORDER BY risk_score DESC LIMIT 20", (result["normalized_value"],)).fetchall()
    return result, matches


@app.route("/ioc-validator")
def ioc_validator():
    return redirect(url_for("ioc_search", q=request.args.get("value", "")))


@app.route("/search")
def ioc_search():
    q = request.args.get("q", "").strip()[:2000]
    result, matches = None, []
    if q:
        conn = connect_db()
        try:
            result, matches = lookup_indicator(conn, q)
        finally:
            conn.close()
        log_activity("IOC_SEARCH", f"Searched indicator type {result['indicator_type'] or 'invalid'}")
    body = """
    <div class="card"><h2>Search indicator</h2>
      <p>Supports IP, domain, URL, hash and CVE. This is a <b>database lookup only</b>: the indicator is never visited,
      resolved, scanned or executed. Try <code>198.51.100.25</code> or <code>login-check.invalid</code>.</p>
      <form method="get"><input name="q" value="{{ q }}" style="width:min(700px,90%)" placeholder="Search indicator" required>
      <button type="submit">Search</button></form></div>
    {% if result %}
    <div class="card"><h2>Result</h2>
      <p>Syntax: {% if result.valid %}<span class="ok">Valid</span>{% else %}<span class="bad">Invalid</span>{% endif %}
         &middot; {{ result.validation_notes }}</p>
      {% if result.valid %}
        <p><b>Indicator type:</b> {{ result.indicator_type }} &nbsp; <b>Normalized:</b> {{ result.normalized_value }}
           &nbsp; <b>Known in demo dataset:</b> {{ 'YES (' ~ matches|length ~ ' record' ~ ('s' if matches|length != 1) ~ ')' if matches else 'NO' }}</p>
        {% for m in matches %}
        <div class="card"><b>{{ m.threat_id }} - {{ m.threat_name }}</b>
          <table>
           <tr><td>Risk</td><td>{{ m.risk_score }}/100 ({{ levels[m.id] }})</td><td>Severity</td><td>{{ sev(m.severity) }}</td></tr>
           <tr><td>Confidence</td><td>{{ m.confidence_score }}%</td><td>Category</td><td>{{ m.category }}</td></tr>
           <tr><td>First seen</td><td>{{ m.first_seen }}</td><td>Last seen</td><td>{{ m.last_seen }}</td></tr>
           <tr><td>Status</td><td>{{ m.status }}</td><td>Source</td><td>{{ m.source }} ({{ m.source_reliability }})</td></tr>
          </table><a href="{{ url_for('threat_detail', threat_pk=m.id) }}">Open full investigation view</a></div>
        {% endfor %}
        {% if matches %}<p class="muted"><b>A match is not a confirmed compromise.</b> Indicators go stale, can be shared by
           benign infrastructure, and may lack context. Validate against internal logs.</p>{% endif %}
      {% endif %}
    </div>{% endif %}"""
    levels = {m["id"]: classify_risk(m["risk_score"]) for m in matches}
    return page("IOC Search & Validator", body, q=q, result=result, matches=matches, levels=levels)


@app.route("/threat/<int:threat_pk>")
@app.route("/indicator/<int:threat_pk>")
def threat_detail(threat_pk):
    conn = connect_db()
    try:
        e = enrich_indicator(conn, threat_pk)
    finally:
        conn.close()
    if e is None:
        abort(404)
    body = """
    <div class="card"><h2>{{ r.threat_id }} &middot; {{ r.threat_name }}</h2>
     <p><span class="badge">{{ e.record_class }}</span> {{ sev(r.severity) }}
        <span class="muted">Record levels: OBSERVATION &rarr; INDICATOR &rarr; ALERT &rarr; THREAT &rarr; INCIDENT. An indicator is not a confirmed attack.</span></p>
     <div class="grid2">
      <table>
       <tr><td>Category</td><td>{{ r.category }}</td></tr><tr><td>Indicator type</td><td>{{ r.type }}</td></tr>
       <tr><td>Indicator value</td><td>{{ r.value }} <span class="muted">(never visit or execute)</span></td></tr>
       <tr><td>Risk score</td><td>{{ r.risk_score }}/100 ({{ e.risk_level }})</td></tr>
       <tr><td>Confidence score</td><td>{{ r.confidence_score }}/100</td></tr>
       <tr><td>Source / reliability</td><td>{{ r.source }} - {{ r.source_reliability }} ({{ e.reliability_label }})</td></tr>
       <tr><td>Observations</td><td>{{ r.observation_count }}</td></tr><tr><td>Status</td><td>{{ r.status }}</td></tr>
       <tr><td>First seen / last seen</td><td>{{ r.first_seen }} / {{ r.last_seen }}</td></tr>
       <tr><td>Campaign / cluster size</td><td>{{ r.campaign_id or 'none' }} / {{ e.cluster_size }}</td></tr>
      </table>
      <div><p><b>How to read the scores:</b> {{ e.interpretation }}</p>
       <p><b>Description:</b> {{ r.description }}</p>
       <p><b>ATT&amp;CK mapping:</b> {% if r.mitre_id %}{{ r.mitre_tactic }} / <a href="{{ url_for('attack_technique', tid=r.mitre_id) }}">{{ r.mitre_id }}</a> {{ r.mitre_technique }}
          {% else %}<span class="muted">None. Context is insufficient, so no mapping is implied.</span>{% endif %}</p>
       {% if e.cve %}<p><b>CVE association:</b> {{ e.cve.cve_id }} - CVSS {{ e.cve.cvss }}, priority {{ e.cve.priority_score }}</p>{% endif %}
      </div></div></div>
    <div class="grid2">
     <div class="card"><h3>Recommended defensive actions</h3><ul>{% for a in e.actions %}<li>{{ a }}</li>{% endfor %}</ul></div>
     <div class="card"><h3>Timeline</h3><ul>{% for when, what in e.timeline %}<li><b>{{ when }}</b> - {{ what }}</li>{% endfor %}</ul></div>
    </div>
    <div class="card"><h3>Related alerts</h3><table><tr><th>ID</th><th>Type</th><th>Severity</th><th>Obs.</th><th>Merged signals</th><th>Status</th><th></th></tr>
      {% for a in e.alerts %}<tr><td>{{ a.id }}</td><td>{{ a.alert_type }}</td><td>{{ sev(a.severity) }}</td><td>{{ a.observation_count }}</td>
        <td>{{ a.merged_events }}</td><td>{{ a.status }}{{ ' / INCIDENT' if a.incident }}</td><td><a href="{{ url_for('soc_case', alert_id=a.id) }}">Open case</a></td></tr>
      {% else %}<tr><td colspan="7">No alerts.</td></tr>{% endfor %}</table></div>
    <div class="card"><h3>Related indicators (same campaign and window)</h3><div class="wrap"><table>
      <tr><th>ID</th><th>Type</th><th>Indicator</th><th>Risk</th><th>Conf.</th><th></th></tr>
      {% for x in e.related %}<tr><td>{{ x.threat_id }}</td><td>{{ x.type }}</td><td>{{ x.value }}</td><td>{{ x.risk_score }}</td><td>{{ x.confidence_score }}</td>
        <td><a href="{{ url_for('threat_detail', threat_pk=x.id) }}">View</a></td></tr>
      {% else %}<tr><td colspan="6">No related indicators. Correlation suggests a relationship, not attribution.</td></tr>{% endfor %}</table></div></div>
    <div class="card"><h3>Analyst notes</h3>
      {% for n in e.notes %}<p>{{ n.note }}<br><small class="muted">{{ n.author }} - {{ n.created_at }}</small></p>{% else %}<p class="muted">No notes yet.</p>{% endfor %}</div>"""
    return page("Threat Detail", body, e=e, r=e["row"])


# ----- Alerts & SOC -----

def alert_rows(conn, where="", params=(), order="a.id DESC", limit=200):
    return conn.execute(f"""SELECT a.*, i.value AS indicator_value, i.threat_id FROM alerts a
        LEFT JOIN indicators i ON i.id = a.indicator_id {where} ORDER BY {order} LIMIT ?""",
                        (*params, limit)).fetchall()


@app.route("/alerts")
def alerts_page():
    status = request.args.get("status", "")
    severity = request.args.get("severity", "")
    cond, params = [], []
    if status in ALERT_STATUSES:
        cond.append("a.status = ?")
        params.append(status)
    if severity in SEVERITIES:
        cond.append("a.severity = ?")
        params.append(severity)
    conn = connect_db()
    try:
        rows = alert_rows(conn, ("WHERE " + " AND ".join(cond)) if cond else "", params,
                          order="a.risk_score DESC, a.id DESC")
    finally:
        conn.close()
    body = """
    <div class="card"><h2>Security alerts</h2>
     <p class="muted">Alerts for the same indicator are merged into one (alert-fatigue control) and keep an observation count.</p>
     <form method="get"><select name="status"><option value="">All statuses</option>{% for s in statuses %}<option {{ 'selected' if request.args.get('status')==s }}>{{ s }}</option>{% endfor %}</select>
      <select name="severity"><option value="">All severities</option>{% for s in severities %}<option {{ 'selected' if request.args.get('severity')==s }}>{{ s }}</option>{% endfor %}</select>
      <button type="submit">Filter</button></form>
     <div class="wrap"><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Risk</th><th>Conf.</th><th>Obs.</th><th>Merged</th><th>Status</th><th>Created</th><th></th></tr>
     {% for a in rows %}<tr><td>{{ a.id }}</td><td>{{ a.title }}</td><td>{{ sev(a.severity) }}</td><td>{{ a.risk_score }}</td><td>{{ a.confidence_score }}%</td>
       <td>{{ a.observation_count }}</td><td>{{ a.merged_events }}</td><td>{{ a.status }}{{ ' / INCIDENT' if a.incident }}</td><td>{{ (a.created_at or '')[:16] }}</td>
       <td><a href="{{ url_for('soc_case', alert_id=a.id) }}">Open case</a></td></tr>{% else %}<tr><td colspan="10">No alerts.</td></tr>{% endfor %}</table></div></div>"""
    return page("Alert Management", body, rows=rows, statuses=ALERT_STATUSES, severities=SEVERITIES)


@app.route("/soc")
def soc_dashboard():
    conn = connect_db()
    try:
        rows = alert_rows(conn, "WHERE a.status IN ('NEW','INVESTIGATING')", order="a.risk_score DESC, a.confidence_score DESC", limit=50)
        counts = dict(pairs(conn.execute("SELECT status, COUNT(*) FROM alerts GROUP BY 1").fetchall()))
        incidents = conn.execute("SELECT COUNT(*) FROM alerts WHERE incident = 1").fetchone()[0]
    finally:
        conn.close()
    body = """
    <div class="cards">{% for s in statuses %}<div class="card"><p class="metric">{{ counts.get(s, 0) }}</p>{{ s }}</div>{% endfor %}
      <div class="card"><p class="metric">{{ incidents }}</p>Declared incidents</div></div>
    <div class="card"><h3>Tier 1 SOC workflow</h3>
      <p>Threat feed &rarr; IOC detected &rarr; validation &rarr; enrichment &rarr; risk + confidence &rarr; alert &rarr; SOC queue &rarr;
      triage &rarr; correlation &rarr; investigation &rarr; escalate / monitor / resolve / false positive &rarr; documentation.</p></div>
    <div class="card"><h2>Triage queue (top 50 by risk, open cases)</h2><div class="wrap"><table>
     <tr><th>Case</th><th>Title</th><th>Severity</th><th>Risk</th><th>Conf.</th><th>Status</th><th></th></tr>
     {% for a in rows %}<tr><td>{{ a.id }}</td><td>{{ a.title }}</td><td>{{ sev(a.severity) }}</td><td>{{ a.risk_score }}</td><td>{{ a.confidence_score }}%</td>
      <td>{{ a.status }}</td><td><a href="{{ url_for('soc_case', alert_id=a.id) }}">Investigate</a></td></tr>
     {% else %}<tr><td colspan="7">Queue is empty.</td></tr>{% endfor %}</table></div></div>"""
    return page("SOC Investigation Queue", body, rows=rows, counts=counts, incidents=incidents, statuses=ALERT_STATUSES)


@app.route("/soc/<int:alert_id>")
def soc_case(alert_id):
    conn = connect_db()
    try:
        alert = conn.execute("""SELECT a.*, i.value AS indicator_value, i.type AS indicator_type, i.category,
            i.mitre_id, i.threat_id FROM alerts a LEFT JOIN indicators i ON i.id = a.indicator_id WHERE a.id = ?""",
                             (alert_id,)).fetchone()
        if alert is None:
            abort(404)
        notes = conn.execute("SELECT * FROM soc_notes WHERE alert_id = ? ORDER BY id DESC", (alert_id,)).fetchall()
    finally:
        conn.close()
    body = """
    <div class="card"><h2>Case #{{ alert.id }} {% if alert.incident %}<span class="badge critical">INCIDENT DECLARED</span>{% endif %}</h2>
     <p><b>{{ alert.title }}</b> {{ sev(alert.severity) }}</p>
     <p>Indicator: {{ alert.indicator_type }} {{ alert.indicator_value }} &middot; <a href="{{ url_for('threat_detail', threat_pk=alert.indicator_id) }}">Open threat detail</a></p>
     <p>Alert type: {{ alert.alert_type }} &middot; Risk {{ alert.risk_score }} &middot; Confidence {{ alert.confidence_score }}% &middot;
        {{ alert.observation_count }} observations &middot; {{ alert.merged_events }} merged signal(s)</p>
     <p>Status: <b>{{ alert.status }}</b> &middot; Created {{ alert.created_at }} &middot; Updated {{ alert.updated_at }}</p></div>
    <div class="card"><h3>Tier 1 triage checklist</h3><ol><li>Confirm the indicator is syntactically valid and current.</li>
     <li>Check internal logs for authorized sightings (do NOT contact the indicator).</li><li>Compare risk vs confidence.</li>
     <li>Review related indicators and ATT&amp;CK context.</li><li>Choose: escalate, monitor, resolve or false positive. Document why.</li></ol></div>
    {% if current_user.role in ['analyst', 'admin'] %}
    <div class="grid2">
     <div class="card"><h3>Update status</h3><form method="post" action="{{ url_for('soc_update_status', alert_id=alert.id) }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><select name="status">{% for s in statuses %}<option {{ 'selected' if alert.status==s }}>{{ s }}</option>{% endfor %}</select>
      <button type="submit">Update</button></form>
      {% if not alert.incident %}<form method="post" action="{{ url_for('soc_declare_incident', alert_id=alert.id) }}">
       <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label><input type="checkbox" name="confirm" value="yes" required> I have evidence this is a real security incident</label>
       <button type="submit">Declare incident</button></form>{% endif %}</div>
     <div class="card"><h3>Add investigation note</h3><form method="post" action="{{ url_for('soc_add_note', alert_id=alert.id) }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><textarea name="note" rows="4" maxlength="5000" style="width:95%" required></textarea>
      <button type="submit">Save note</button></form></div></div>
    {% else %}<div class="card muted">Your role is read-only (viewer).</div>{% endif %}
    <div class="card"><h3>Investigation history</h3>{% for n in notes %}<p>{{ n.note }}<br><small class="muted">{{ n.author }} - {{ n.created_at }}</small></p>
     {% else %}<p class="muted">No notes yet.</p>{% endfor %}</div>"""
    return page("SOC Case", body, alert=alert, notes=notes, statuses=ALERT_STATUSES)


def update_alert_status(conn, alert_id, status):
    cur = conn.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
                       (status, datetime.now().isoformat(timespec="seconds"), alert_id))
    conn.commit()
    return cur.rowcount


@app.route("/soc/<int:alert_id>/status", methods=["POST"])
@roles_required("analyst", "admin")
def soc_update_status(alert_id):
    status = request.form.get("status", "")
    if status not in ALERT_STATUSES:
        abort(400, "Invalid status")
    conn = connect_db()
    try:
        changed = update_alert_status(conn, alert_id, status)
    finally:
        conn.close()
    if not changed:
        abort(404)
    log_activity("SOC_STATUS_CHANGED", f"Case {alert_id} -> {status}")
    return redirect(url_for("soc_case", alert_id=alert_id))


@app.route("/soc/<int:alert_id>/incident", methods=["POST"])
@roles_required("analyst", "admin")
def soc_declare_incident(alert_id):
    if request.form.get("confirm") != "yes":
        abort(400, "Confirmation required to declare an incident")
    conn = connect_db()
    try:
        cur = conn.execute("UPDATE alerts SET incident = 1, status = 'INVESTIGATING', updated_at = ? WHERE id = ?",
                           (datetime.now().isoformat(timespec="seconds"), alert_id))
        conn.commit()
    finally:
        conn.close()
    if not cur.rowcount:
        abort(404)
    log_activity("INCIDENT_DECLARED", f"Case {alert_id}")
    return redirect(url_for("soc_case", alert_id=alert_id))


@app.route("/soc/<int:alert_id>/notes", methods=["POST"])
@roles_required("analyst", "admin")
def soc_add_note(alert_id):
    note = request.form.get("note", "").strip()
    if not note or len(note) > 5000:
        abort(400, "Note must be 1-5000 characters")
    conn = connect_db()
    try:
        if conn.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
            abort(404)
        conn.execute("INSERT INTO soc_notes (alert_id, author, note, created_at) VALUES (?,?,?,?)",
                     (alert_id, current_user.username, note, datetime.now().isoformat(timespec="seconds")))
        conn.commit()
    finally:
        conn.close()
    log_activity("SOC_NOTE_ADDED", f"Note added to case {alert_id}")
    return redirect(url_for("soc_case", alert_id=alert_id))


# ----- Correlation & ATT&CK -----

@app.route("/correlation")
def correlation_page():
    conn = connect_db()
    try:
        rows = conn.execute("SELECT id, campaign_id, category, type, first_seen, last_seen, risk_score, confidence_score "
                            "FROM indicators WHERE campaign_id IS NOT NULL").fetchall()
        clusters = correlate_threats(rows)
    finally:
        conn.close()
    body = """
    <div class="card"><h2>Related threat clusters</h2>
     <p>Records are grouped when they share a campaign ID and an observation window. Correlation shows a <b>relationship</b>,
     not guaranteed attribution.</p>
     <p class="muted">{{ clusters|length }} clusters. Showing the 60 with highest risk.</p>
     <div class="wrap"><table><tr><th>Cluster</th><th>Category</th><th>Members</th><th>Types</th><th>Max risk</th><th>Avg conf.</th><th>Window</th></tr>
     {% for c in clusters[:60] %}<tr><td><a href="{{ url_for('cluster_detail', cluster_id=c.cluster_id) }}">{{ c.cluster_id }}</a></td><td>{{ c.category }}</td>
      <td>{{ c.size }}</td><td>{{ c.types|join(', ') }}</td><td>{{ c.max_risk }}</td><td>{{ c.avg_conf }}%</td>
      <td>{{ c.first_seen[:10] }} to {{ c.last_seen[:10] }}</td></tr>{% endfor %}</table></div></div>"""
    return page("Threat Correlation", body, clusters=clusters)


@app.route("/correlation/<cluster_id>")
def cluster_detail(cluster_id):
    if not re.fullmatch(r"CMP-[A-Z0-9]+-W\d+", cluster_id):
        abort(404)
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM indicators WHERE campaign_id IS NOT NULL").fetchall()
        cluster = next((c for c in correlate_threats(rows) if c["cluster_id"] == cluster_id), None)
        if cluster is None:
            abort(404)
        marks = ",".join("?" * len(cluster["member_ids"]))
        members = conn.execute(f"SELECT * FROM indicators WHERE id IN ({marks}) ORDER BY first_seen",
                               cluster["member_ids"]).fetchall()
    finally:
        conn.close()
    body = """
    <div class="card"><p>{{ c.category }} &middot; {{ c.size }} related records &middot; types: {{ c.types|join(', ') }}</p>
     <div class="wrap"><table><tr><th>ID</th><th>Type</th><th>Indicator</th><th>Risk</th><th>Conf.</th><th>First seen</th><th></th></tr>
     {% for m in members %}<tr><td>{{ m.threat_id }}</td><td>{{ m.type }}</td><td>{{ m.value }}</td><td>{{ m.risk_score }}</td><td>{{ m.confidence_score }}%</td>
      <td>{{ m.first_seen[:10] }}</td><td><a href="{{ url_for('threat_detail', threat_pk=m.id) }}">View</a></td></tr>{% endfor %}</table></div></div>"""
    return page(f"Cluster {cluster_id}", body, c=cluster, members=members)


@app.route("/attack")
def attack_page():
    conn = connect_db()
    try:
        tactics = pairs(conn.execute("SELECT mitre_tactic, COUNT(*) c FROM indicators WHERE mitre_id IS NOT NULL "
                                     "GROUP BY 1 ORDER BY c DESC").fetchall())
        techniques = conn.execute("SELECT mitre_id, mitre_technique, mitre_tactic, COUNT(*) AS total FROM indicators "
                                  "WHERE mitre_id IS NOT NULL GROUP BY 1,2,3 ORDER BY total DESC").fetchall()
        unmapped = conn.execute("SELECT COUNT(*) FROM indicators WHERE mitre_id IS NULL").fetchone()[0]
    finally:
        conn.close()
    body = """
    <div class="card"><p>An IOC says <b>what</b> was observed. ATT&amp;CK describes <b>how behavior</b> relates to adversary techniques.
     A tactic is the adversary's goal, a technique is how it may be achieved. Records are mapped <b>only when context is sufficient</b>;
     {{ unmapped }} records are intentionally unmapped.</p></div>
    <div class="grid2">{{ bars('Threats by tactic', tactics) }}
     <div class="card"><h3>Technique frequency</h3><table><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Records</th></tr>
      {% for t in techniques %}<tr><td><a href="{{ url_for('attack_technique', tid=t.mitre_id) }}">{{ t.mitre_id }}</a></td><td>{{ t.mitre_technique }}</td>
       <td>{{ t.mitre_tactic }}</td><td>{{ t.total }}</td></tr>{% endfor %}</table></div></div>"""
    return page("MITRE ATT&CK Mapping", body, tactics=tactics, techniques=techniques, unmapped=unmapped)


@app.route("/attack/<tid>")
def attack_technique(tid):
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
        abort(404)
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM indicators WHERE mitre_id = ? ORDER BY risk_score DESC LIMIT 100", (tid,)).fetchall()
    finally:
        conn.close()
    body = """
    <div class="card"><p class="muted">Top 100 synthetic records mapped to this technique.</p><div class="wrap"><table>
     <tr><th>ID</th><th>Type</th><th>Indicator</th><th>Category</th><th>Risk</th><th>Conf.</th><th></th></tr>
     {% for m in rows %}<tr><td>{{ m.threat_id }}</td><td>{{ m.type }}</td><td>{{ m.value }}</td><td>{{ m.category }}</td><td>{{ m.risk_score }}</td>
      <td>{{ m.confidence_score }}%</td><td><a href="{{ url_for('threat_detail', threat_pk=m.id) }}">View</a></td></tr>
     {% else %}<tr><td colspan="7">No records.</td></tr>{% endfor %}</table></div></div>"""
    return page(f"Technique {tid}", body, rows=rows)


# ----- Vulnerabilities -----

@app.route("/cve")
def cve_page():
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM cves ORDER BY priority_score DESC").fetchall()
        by_cvss = {r["cve_id"]: n for n, r in enumerate(sorted(rows, key=lambda r: -r["cvss"]), 1)}
    finally:
        conn.close()
    body = """
    <div class="card"><h2>Vulnerability prioritization</h2>
     <p>CVSS alone should not decide patch order. Priority = CVSS + asset criticality + exposure + exploitation evidence + patch availability.
     Example: <b>CVE-2099-0001</b> (CVSS 9.8, isolated test asset) ranks below <b>CVE-2099-0002</b> (CVSS 7.8, internet-facing critical system with demo exploitation evidence).
     CVE-2099-xxxx IDs are <b>fictional</b>. No exploitation details are provided.</p>
     <div class="wrap"><table><tr><th>CVE (demo)</th><th>Product</th><th>CVSS</th><th>CVSS rank</th><th>Asset crit.</th><th>Exposure</th><th>Exploitation</th><th>Patch</th><th>Priority</th></tr>
     {% for c in rows %}<tr><td>{{ c.cve_id }}</td><td>{{ c.product_category }}</td><td>{{ c.cvss }} {{ sev(c.severity) }}</td><td>#{{ by_cvss[c.cve_id] }}</td>
      <td>{{ c.asset_criticality }}/5</td><td>{{ c.exposure }}</td><td>{{ c.exploitation_status_demo }}</td><td>{{ 'Yes' if c.patch_available else 'No' }}</td>
      <td><b>{{ c.priority_score }}</b></td></tr>{% endfor %}</table></div></div>"""
    return page("Vulnerability Awareness", body, rows=rows, by_cvss=by_cvss)


# ----- Awareness, quiz, executive, IR guide -----

@app.route("/awareness")
def awareness_page():
    body = """
    <div class="card"><p>Fifteen short modules. Each answers: what is it, why it matters, warning signs, safe practices, and what to do if something happens.</p>
    {% for m in modules %}<details><summary>{{ m[0] }}</summary>
     <p><b>What is it?</b> {{ m[1] }}</p><p><b>Why does it matter?</b> {{ m[2] }}</p><p><b>Warning signs:</b> {{ m[3] }}</p>
     <p><b>Safe practices:</b> {{ m[4] }}</p><p><b>If something happens:</b> {{ m[5] }}</p></details>{% endfor %}
    <p><a class="button" href="{{ url_for('quiz_page') }}">Take the quiz</a></p></div>"""
    return page("Cybersecurity Awareness Center", body, modules=AWARENESS_MODULES)


@app.route("/quiz", methods=["GET", "POST"])
def quiz_page():
    result = None
    if request.method == "POST":
        answers = {}
        for i in range(len(QUIZ)):
            val = request.form.get(f"q{i}", type=int)
            if val is not None and 0 <= val < 4:
                answers[i] = val
        result = score_quiz(answers)
        conn = connect_db()
        try:
            conn.execute("INSERT INTO quiz_results (anon_id, overall_score, category_scores, created_at) VALUES (?,?,?,?)",
                         (hashlib.sha256(current_user.username.encode()).hexdigest()[:12], result["overall"],
                          json.dumps(result["categories"]), datetime.now().isoformat(timespec="seconds")))
            conn.commit()
        finally:
            conn.close()
        log_activity("QUIZ_SUBMITTED", f"Score {result['overall']}")
    body = """
    {% if result %}
    <div class="card"><h2>Awareness score: {{ result.overall }}/100 - {{ result.band }}</h2>
     <p class="muted">This is an educational score. It is not a judgment of anyone's competence or fitness for a job.</p>
     {{ bars('Category scores (%)', result.categories.items()|list) }}
     <h3>Learning recommendations</h3><ul>{% for r in result.recommendations %}<li><b>{{ r.category }}</b> ({{ r.score }}%): {{ r.text }}</li>{% endfor %}</ul>
     <p><a class="button" href="{{ url_for('awareness_page') }}">Open Awareness Center</a> <a class="button" href="{{ url_for('quiz_page') }}">Retake</a></p></div>
    {% else %}
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
     {% for q in quiz %}{% set i = loop.index0 %}<div class="card"><b>{{ loop.index }}. [{{ q[0] }}]</b> {{ q[1] }}
      {% for opt in q[2] %}<div><label><input type="radio" name="q{{ i }}" value="{{ loop.index0 }}"> {{ 'ABCD'[loop.index0] }}. {{ opt }}</label></div>{% endfor %}</div>{% endfor %}
     <button type="submit">Submit quiz</button></form>
    {% endif %}"""
    return page("Security Awareness Quiz", body, result=result, quiz=QUIZ)


@app.route("/executive")
def executive_page():
    conn = connect_db()
    try:
        stats = dashboard_stats(conn)
        top_cats = conn.execute("SELECT category, COUNT(*) c FROM indicators WHERE severity IN ('High','Critical') "
                                "GROUP BY 1 ORDER BY c DESC LIMIT 3").fetchall()
        vuln_cats = conn.execute("SELECT product_category, ROUND(AVG(priority_score)) FROM cves "
                                 "GROUP BY 1 ORDER BY 2 DESC LIMIT 3").fetchall()
        urgent_vulns = conn.execute("SELECT COUNT(*) FROM cves WHERE priority_score >= 61").fetchone()[0]
        results = conn.execute("SELECT overall_score, category_scores, created_at FROM quiz_results ORDER BY id DESC LIMIT 200").fetchall()
        risky = conn.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING') AND risk_score >= 61").fetchone()[0]
    finally:
        conn.close()
    by_day, weak = defaultdict(list), defaultdict(list)
    for r in results:
        by_day[r["created_at"][:10]].append(r["overall_score"])
        for cat, s in json.loads(r["category_scores"]).items():
            weak[cat].append(s)
    trend = [(d, round(sum(v) / len(v))) for d, v in sorted(by_day.items())][-7:]
    weakest = sorted(((c, round(sum(v) / len(v))) for c, v in weak.items()), key=lambda x: x[1])[:3]
    priorities = []
    if risky:
        priorities.append(f"Review the {risky} open high-risk alerts, starting with the highest confidence.")
    if urgent_vulns:
        priorities.append(f"Patch or mitigate the {urgent_vulns} high-priority vulnerabilities first (exposed, exploited, critical assets).")
    if top_cats:
        priorities.append(f"Focus awareness reminders on {top_cats[0][0]}, the most common serious category.")
    if weakest:
        priorities.append(f"Offer refresher training on {weakest[0][0]}, currently the weakest awareness area.")
    body = """
    <div class="cards">
      <div class="card"><p class="metric">{{ s.total_threat_records }}</p>Threat records tracked</div>
      <div class="card"><p class="metric">{{ s.critical_threats + s.high_threats }}</p>Critical / high severity</div>
      <div class="card"><p class="metric">{{ s.open_investigations }}</p>Open investigations</div>
      <div class="card"><p class="metric">{{ s.vulnerabilities_tracked }}</p>Vulnerabilities tracked</div></div>
    <div class="grid2">{{ bars('Top serious threat categories', top_cats) }}{{ bars('Top vulnerability areas (avg priority)', vuln_cats) }}
     {{ bars('Awareness score trend (daily average)', trend) }}{{ bars('Top awareness weaknesses (avg %)', weakest) }}</div>
    <div class="card"><h2>Recommended defensive priorities</h2><ol>{% for p in priorities %}<li>{{ p }}</li>{% else %}<li>No urgent priorities from current data.</li>{% endfor %}</ol>
     <p class="muted">Plain-language summary of synthetic data. High scores indicate concern, not confirmed compromise.</p></div>"""
    return page("Executive Cybersecurity Summary", body, s=stats, top_cats=pairs(top_cats), vuln_cats=pairs(vuln_cats),
                trend=trend, weakest=weakest, priorities=priorities)


@app.route("/incident-response")
def ir_guide():
    body = """
    <div class="card"><h2>Incident-response lifecycle (high level)</h2>
     <p>Preparation &rarr; Detection / Identification &rarr; Containment &rarr; Eradication &rarr; Recovery &rarr; Lessons learned.
     Frameworks use slightly different terms, but the idea is the same.</p>
     <h3>Educational checklist</h3><ol><li>Note what you saw, when, and on which system.</li><li>Do not delete evidence or "clean up" alone.</li>
     <li>Report to the security team through the official channel.</li><li>Follow containment instructions (for example disconnecting a device).</li>
     <li>Preserve logs and screenshots for responders.</li><li>After recovery, review what worked and update defenses.</li></ol></div>
    <div class="card"><h2>Why intelligence is never absolute</h2><ul>
     <li>An IP may be shared by many users, and a domain can change owner.</li><li>Cloud infrastructure can host benign and malicious services.</li>
     <li>Indicators go stale and feeds can disagree.</li><li>Correlation does not prove attribution.</li></ul>
     <p>Threat intelligence should support analyst decisions, not replace them.</p></div>"""
    return page("Incident Response Awareness", body)


# ----- Audit (admin only) -----

def audit_query():
    action = request.args.get("action", "").strip()[:80]
    username = request.args.get("username", "").strip()[:80]
    clauses, params = [], []
    for col, val in (("action", action), ("username", username)):
        if val:
            clauses.append(f"{col} LIKE ?")
            params.append(f"%{val}%")
    return action, username, (" WHERE " + " AND ".join(clauses)) if clauses else "", params


@app.route("/audit")
@roles_required("admin")
def audit_page():
    action, username, where_sql, params = audit_query()
    conn = connect_db()
    try:
        total = conn.execute("SELECT COUNT(*) FROM audit_logs" + where_sql, params).fetchone()[0]
        page_no, pages = paginate(total, request.args.get("page", 1, type=int) or 1)
        rows = conn.execute("SELECT * FROM audit_logs" + where_sql + " ORDER BY id DESC LIMIT ? OFFSET ?",
                            params + [PER_PAGE, (page_no - 1) * PER_PAGE]).fetchall()
    finally:
        conn.close()
    body = """
    <div class="card"><p class="muted">Local demonstration log. Not tamper-proof.</p>
     <form method="get"><input name="username" value="{{ username }}" placeholder="Filter username"><input name="action" value="{{ action }}" placeholder="Filter action">
      <button type="submit">Search</button> <a href="{{ url_for('audit_export', username=username, action=action) }}">Export CSV</a></form>
     <p>{{ total }} events. Page {{ page_no }} of {{ pages }}.</p>
     <div class="wrap"><table><tr><th>ID</th><th>User</th><th>Action</th><th>Details</th><th>Time</th></tr>
     {% for r in rows %}<tr><td>{{ r.id }}</td><td>{{ r.username }}</td><td>{{ r.action }}</td><td>{{ r.details }}</td><td>{{ r.created_at }}</td></tr>{% endfor %}</table></div>
     {% if page_no > 1 %}<a href="{{ url_for('audit_page', username=username, action=action, page=page_no-1) }}">&larr; Previous</a>{% endif %}
     {% if page_no < pages %} <a href="{{ url_for('audit_page', username=username, action=action, page=page_no+1) }}">Next &rarr;</a>{% endif %}</div>"""
    return page("Security Audit Logs", body, rows=rows, total=total, username=username, action=action,
                page_no=page_no, pages=pages)


@app.route("/audit/export")
@roles_required("admin")
def audit_export():
    _a, _u, where_sql, params = audit_query()
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM audit_logs" + where_sql + " ORDER BY id DESC LIMIT 10000", params).fetchall()
    finally:
        conn.close()
    safe = lambda v: "'" + str(v) if str(v)[:1] in "=+-@" else v     # block CSV formula injection
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(["id", "username", "action", "details", "created_at"])
    writer.writerows([[safe(c) for c in tuple(r)] for r in rows])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})


# ============================================================
# 8. REST API  (login required; POST/PUT need the X-CSRFToken header)
# ============================================================

@app.route("/api/validate-ioc")
def api_validate_ioc():
    value = request.args.get("value", "").strip()
    if not value:
        return jsonify({"error": "Missing value parameter"}), 400
    return jsonify({"input": value, **validate_indicator(value)})


@app.route("/api/indicators")
def api_indicators():
    cond, params = [], []
    for col, allowed in (("severity", SEVERITIES), ("type", TYPES), ("category", CATEGORIES), ("status", IND_STATUSES)):
        if request.args.get(col, "") in allowed:
            cond.append(f"{col} = ?")
            params.append(request.args[col])
    limit = min(max(request.args.get("limit", 100, type=int) or 100, 1), 500)
    offset = max(request.args.get("offset", 0, type=int) or 0, 0)
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM indicators" + ((" WHERE " + " AND ".join(cond)) if cond else "")
                            + " ORDER BY id LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/indicators/search")
def api_indicator_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Missing q parameter"}), 400
    conn = connect_db()
    try:
        result, matches = lookup_indicator(conn, q)
    finally:
        conn.close()
    return jsonify({"validation": result, "known_in_demo_dataset": bool(matches),
                    "matches": [dict(m) for m in matches],
                    "note": "Database lookup only. A match is not a confirmed compromise."})


@app.route("/api/indicators/<int:pk>")
def api_indicator(pk):
    conn = connect_db()
    try:
        e = enrich_indicator(conn, pk)
    finally:
        conn.close()
    if e is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"indicator": dict(e["row"]), "record_class": e["record_class"], "risk_level": e["risk_level"],
                    "related": [dict(r) for r in e["related"]], "alerts": [dict(a) for a in e["alerts"]],
                    "notes": [dict(n) for n in e["notes"]], "recommended_actions": e["actions"]})


@app.route("/api/dashboard/stats")
def api_stats():
    conn = connect_db()
    try:
        return jsonify(dashboard_stats(conn))
    finally:
        conn.close()


@app.route("/api/dashboard/trends")
def api_trends():
    conn = connect_db()
    try:
        rows = conn.execute("SELECT strftime('%Y-%m-%d', first_seen, 'weekday 0', '-6 days') AS week, COUNT(*) AS total "
                            "FROM indicators GROUP BY week ORDER BY week").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/alerts")
def api_alerts():
    conn = connect_db()
    try:
        rows = alert_rows(conn, limit=500, order="a.risk_score DESC, a.id DESC")
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/alerts/<int:alert_id>/status", methods=["PUT", "POST"])
@roles_required("analyst", "admin")
def api_alert_status(alert_id):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ALERT_STATUSES:
        return jsonify({"error": "Invalid status", "allowed": ALERT_STATUSES}), 400
    conn = connect_db()
    try:
        changed = update_alert_status(conn, alert_id, status)
    finally:
        conn.close()
    if not changed:
        return jsonify({"error": "Alert not found"}), 404
    log_activity("API_ALERT_STATUS_CHANGED", f"Alert {alert_id} -> {status}")
    return jsonify({"message": "Status updated", "status": status})


@app.route("/api/cves")
def api_cves():
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM cves ORDER BY priority_score DESC").fetchall()
    finally:
        conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/awareness/modules")
def api_modules():
    keys = ("title", "what", "why", "warning_signs", "safe_practices", "if_something_happens")
    return jsonify([dict(zip(keys, m)) for m in AWARENESS_MODULES])


@app.route("/api/quiz")
def api_quiz():
    return jsonify([{"id": i, "category": q[0], "question": q[1], "options": q[2]} for i, q in enumerate(QUIZ)])


@app.route("/api/quiz/submit", methods=["POST"])
def api_quiz_submit():
    raw = (request.get_json(silent=True) or {}).get("answers")
    if not isinstance(raw, dict):
        return jsonify({"error": "Body must be {\"answers\": {\"0\": 2, ...}}"}), 400
    try:
        answers = {int(k): int(v) for k, v in raw.items()}
    except (TypeError, ValueError):
        return jsonify({"error": "Answers must be integers"}), 400
    return jsonify(score_quiz(answers))


# ============================================================
# 9. CLI COMMANDS & START
# ============================================================

@app.cli.command("create-user")
def create_user():
    """Create a user: flask --app app create-user"""
    init_db()
    username = input("Username: ").strip()
    role = input(f"Role {ROLES} [admin]: ").strip().lower() or "admin"
    if not username or role not in ROLES:
        print("Invalid username or role.")
        return
    password = getpass("Password (min 12 chars): ")
    if len(password) < 12 or password != getpass("Confirm password: "):
        print("Password too short or does not match.")
        return
    conn = connect_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                     (username, generate_password_hash(password), role, datetime.now().isoformat(timespec="seconds")))
        conn.commit()
        print(f"User '{username}' created with role '{role}'.")
    except sqlite3.IntegrityError:
        print("That username already exists.")
    finally:
        conn.close()


@app.cli.command("reseed")
def reseed():
    """Rebuild synthetic threat data: flask --app app reseed"""
    conn = connect_db()
    for table in ("soc_notes", "alerts", "indicators", "cves", "quiz_results"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
    init_db()
    print("Synthetic data regenerated.")


# Create / migrate the database on EVERY start (python app.py, flask run, etc.).
init_db()

@app.cli.command("create-admin")
def create_admin():
    """Create an administrator account."""
    init_db()

    username = input("Enter admin username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    from getpass import getpass
    password = getpass("Enter admin password: ")
    confirm = getpass("Confirm admin password: ")

    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    if password != confirm:
        print("Passwords do not match.")
        return

    conn = connect_db()
    try:
        conn.execute(
            """
            INSERT INTO users
                (username, password_hash, role, created_at)
            VALUES (?, ?, 'admin', ?)
            """,
            (
                username,
                generate_password_hash(password),
                datetime.now().isoformat(timespec="seconds")
            )
        )
        conn.commit()
        print("Administrator created successfully.")
    except sqlite3.IntegrityError:
        print("That username already exists.")
    finally:
        conn.close()

if __name__ == "__main__":
    # Local development only. Do not expose this server publicly.
    app.run(host="127.0.0.1", port=5000, debug=False)
