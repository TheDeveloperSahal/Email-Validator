import io
import random
import re
import smtplib
import socket
import string
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta

import dns.exception
import dns.resolver
import pandas as pd
import requests
import streamlit as st
from email_validator import EmailNotValidError, validate_email


def load_css():
    try:
        with open("style.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except Exception:
        pass


# ==================== CONFIG ====================

@st.cache_data(ttl=86400)
def fetch_disposable_domains():
    url = ("https://raw.githubusercontent.com/disposable-email-domains/"
           "disposable-email-domains/main/disposable_email_blocklist.conf")
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            return {l.strip().lower() for l in r.text.splitlines()
                    if l.strip() and not l.startswith("#")}
    except Exception:
        pass
    return set()


EXTRA_DISPOSABLE = {
    "tempmail.org", "tempmail.net", "throwawaymail.com", "guerrillamailblock.com",
    "disposable-mail.com", "sharklasers.com", "trashmail.com", "10minutemail.com",
    "maildrop.cc", "tempemail.cc", "getnada.com", "mohmal.com", "dispostable.com",
    "emailondeck.com", "fakeinbox.com", "grr.la", "mailnesia.com", "tempinbox.com",
    "tempail.com", "throwaway.email", "mailinator2.com", "binkmail.com", "bobmail.info",
    "chammy.info", "devnullmail.com", "letthemeatspam.com", "reallymymail.com",
    "reconmail.com", "safetymail.info", "sendspamhere.com", "sogetthis.com",
    "spambooger.com", "spamherelots.com", "spamhereplease.com", "20minutemail.com",
    "30minutemail.com", "mail.lukasstorck.com", "pro.anonymail.co", "shootstack.net",
    "kriscop.online", "tsaur.com", "furusato.dev", "0-mail.com", "0815.ru",
    "0clickemail.com", "0wnd.net", "0wnd.org", "1fsdfdsfsdf.tk", "1pad.de",
    "2fdgdfgdfgdf.tk", "mailinator.com", "yopmail.com", "guerrillamail.com",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "icloud.com", "protonmail.com", "proton.me", "zoho.com", "yandex.com", "mail.com",
    "gmx.com", "live.com", "msn.com", "comcast.net", "verizon.net", "tutanota.com",
    "tuta.com",
}

ROLE_PREFIXES = {
    "info", "admin", "contact", "hello", "support", "sales", "editor", "editors",
    "office", "team", "press", "media", "webmaster", "help", "enquiries", "inquiries",
    "mail", "service", "submissions", "news", "newsroom",
}

RESOLVER = dns.resolver.Resolver()
RESOLVER.lifetime = 8

FIELDS = ["Deliverability", "Notes/Issues", "Send_Recommendation", "Syntax Valid",
          "Domain Valid", "Mailbox Exists", "Disposable Email", "Free Email",
          "Catch-All Domain", "SPF Record", "Role Based", "MX Host", "SMTP Code"]


# ==================== DNS ====================

def validate_syntax(email):
    try:
        validate_email(email, check_deliverability=False)  # syntax only; we do DNS ourselves
        return True
    except EmailNotValidError:
        return False


def dns_lookup(domain):
    """Returns (status, mx_hosts_sorted_by_priority).
    status: ok | nxdomain | no_mail | dns_error"""
    try:
        ans = RESOLVER.resolve(domain, "MX")
        recs = sorted((r.preference, str(r.exchange).rstrip(".")) for r in ans)
        if len(recs) == 1 and recs[0][1] == "":  # null MX
            return "no_mail", []
        return "ok", [h for _, h in recs]
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        try:
            RESOLVER.resolve(domain, "A")
            return "ok", [domain]
        except dns.resolver.NXDOMAIN:
            return "nxdomain", []
        except dns.exception.DNSException:
            return "no_mail", []
    except dns.exception.DNSException:
        return "dns_error", []


def check_spf_record(domain):
    try:
        for rdata in RESOLVER.resolve(domain, "TXT"):
            if "v=spf1" in "".join(s.decode() for s in rdata.strings).lower():
                return True
    except Exception:
        pass
    return False


def is_disposable(domain):
    return domain in DISPOSABLE_DOMAINS or domain in EXTRA_DISPOSABLE


# ==================== SMTP ====================

HARD_REJECT = ("5.1.1", "5.1.10", "5.1.0", "user unknown", "unknown user", "no such user",
               "does not exist", "recipient not found", "mailbox unavailable",
               "mailbox not found", "invalid recipient", "no mailbox")
BLOCK_WORDS = ("block", "spam", "reputation", "blacklist", "spamhaus", "rbl", "listed",
               "policy", "denied", "not allowed", "relay")


def classify_reply(code, msg):
    """accepted | rejected (mailbox truly missing) | temp | blocked (our check was refused)"""
    low = msg.lower()
    if code in (250, 251):
        return "accepted"
    if 400 <= code < 500:
        return "temp"
    if any(h in low for h in HARD_REJECT):
        return "rejected"
    if any(w in low for w in BLOCK_WORDS):
        return "blocked"
    if code in (550, 551, 553):
        return "rejected"
    return "blocked"


def smtp_probe(hosts, addr, helo, mail_from, timeout):
    """Returns (state, code). state: accepted|rejected|temp|blocked|unreachable"""
    for host in hosts[:3]:
        server = None
        try:
            server = smtplib.SMTP(timeout=timeout, local_hostname=helo or None)
            server.connect(host, 25)
            server.ehlo_or_helo_if_needed()
            server.mail(mail_from)
            code, msg = server.rcpt(addr)
            msg = msg.decode(errors="ignore") if isinstance(msg, bytes) else str(msg)
            return classify_reply(code, msg), code
        except (smtplib.SMTPException, socket.timeout, OSError):
            continue
        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass
                try:
                    server.close()
                except Exception:
                    pass
    return "unreachable", None


@st.cache_data(ttl=300)
def port25_works():
    try:
        socket.create_connection(("gmail-smtp-in.l.google.com", 25), timeout=8).close()
        return True
    except OSError:
        return False


# ==================== VERDICT ====================
# "Deliverable" is only given when the mail server itself confirmed the mailbox.

def get_status(r):
    if not r["syntax"]:
        return "Not Deliverable", "Invalid syntax", "Do not send"
    if r["dns"] == "nxdomain":
        return "Not Deliverable", "Domain doesn't exist", "Do not send"
    if r["dns"] == "no_mail":
        return "Not Deliverable", "Domain has no mail server", "Do not send"
    if r["disposable"]:
        return "Not Deliverable", "Disposable domain", "Do not send"
    if r["smtp"] == "rejected":
        return "Not Deliverable", "Mailbox does not exist (server rejected it)", "Do not send"
    if r["dns"] == "dns_error":
        return "Unknown", "DNS lookup failed - retry", "Hold and re-check"
    if r["smtp"] == "accepted":
        if r["catch_all"]:
            return "Risky", "Catch-all enabled - mailbox unconfirmed", "Send in small batch"
        if r["free"]:
            return "Deliverable", "Free email provider - mailbox confirmed", "Send"
        note = "Mailbox confirmed"
        if r["role"]:
            note += " (role address)"
        if not r["spf"]:
            note += " - domain has no SPF"
        return "Deliverable", note, "Send"
    reasons = {
        "temp": "Server deferred the check (greylisting) - retry later",
        "blocked": "Server refused the check - mailbox unconfirmed",
        "unreachable": "Mail server unreachable on port 25 - mailbox unconfirmed",
        "skipped": "Mailbox check skipped - mailbox unconfirmed",
    }
    note = reasons.get(r["smtp"], "Mailbox unconfirmed")
    if r["free"]:
        note = "Free email provider - mailbox unverified"
    return "Unknown", note, "Hold and re-check"


def to_row(r):
    deliverability, notes, rec = get_status(r)
    return {
        "Email": r["email"], "Deliverability": deliverability, "Notes/Issues": notes,
        "Send_Recommendation": rec, "Syntax Valid": r["syntax"],
        "Domain Valid": r["dns"] == "ok",
        "Mailbox Exists": r["smtp"] == "accepted" and not r["catch_all"],
        "Disposable Email": r["disposable"], "Free Email": r["free"],
        "Catch-All Domain": r["catch_all"], "SPF Record": r["spf"],
        "Role Based": r["role"], "MX Host": r["mx"], "SMTP Code": r["code"],
    }


def blank(email, **kw):
    r = {"email": email, "syntax": True, "dns": "skipped", "spf": False, "catch_all": False,
         "disposable": False, "free": False, "role": False, "mx": "", "smtp": "skipped",
         "code": ""}
    r.update(kw)
    return r


# ==================== PER-DOMAIN WORKER ====================
# DNS, SPF and catch-all are checked ONCE per domain, domains run in parallel,
# and emails on the same domain run one after another (polite to the mail server).

def check_domain(domain, emails, cfg):
    dstat, hosts = dns_lookup(domain)
    ok = dstat == "ok"
    spf = check_spf_record(domain) if ok else False
    free = domain in FREE_EMAIL_DOMAINS
    disposable = is_disposable(domain)
    do_smtp = ok and not cfg["skip_smtp"] and not disposable

    catch_all = False
    if do_smtp and not free:
        junk = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        state, _ = smtp_probe(hosts, f"zz{junk}@{domain}", cfg["helo"], cfg["mail_from"], cfg["timeout"])
        catch_all = state == "accepted"

    rows = []
    for e in emails:
        local = e.rsplit("@", 1)[0].lower()
        r = blank(e, dns=dstat, spf=spf, free=free, disposable=disposable,
                  catch_all=catch_all, role=local in ROLE_PREFIXES,
                  mx=hosts[0] if hosts else "")
        if do_smtp:
            state, code = smtp_probe(hosts, e, cfg["helo"], cfg["mail_from"], cfg["timeout"])
            if state == "temp":  # greylisting: wait and try once more
                time.sleep(cfg["retry_wait"])
                state, code = smtp_probe(hosts, e, cfg["helo"], cfg["mail_from"], cfg["timeout"])
            r["smtp"], r["code"] = state, code or ""
            time.sleep(cfg["delay"])
        rows.append(to_row(r))
    return rows


def safe_check_domain(domain, emails, cfg):
    try:
        return check_domain(domain, emails, cfg)
    except Exception as ex:  # one bad domain must never crash the whole run
        out = []
        for e in emails:
            row = to_row(blank(e, dns="dns_error"))
            row["Notes/Issues"] = f"Check failed: {str(ex)[:60]}"
            out.append(row)
        return out


def validate_batch(emails, cfg, on_progress=None):
    results, groups = {}, defaultdict(list)
    for e in emails:
        if "@" not in e or not validate_syntax(e):
            results[e] = to_row(blank(e, syntax=False))
        else:
            groups[e.rsplit("@", 1)[1].lower()].append(e)
    total = len(emails)
    if on_progress and results:
        on_progress(list(results.values()), len(results), total)
    with ThreadPoolExecutor(max_workers=cfg["workers"]) as ex:
        futures = [ex.submit(safe_check_domain, d, es, cfg) for d, es in groups.items()]
        for fut in as_completed(futures):
            for row in fut.result():
                results[row["Email"]] = row
            if on_progress:
                on_progress(list(results.values()), len(results), total)
    return [results[e] for e in emails]


# ==================== UI HELPERS ====================

def format_time(seconds):
    return str(timedelta(seconds=int(seconds)))


def color_status(val):
    return {
        "Deliverable": "background-color: #d4edda; color: #155724",
        "Risky": "background-color: #fff3cd; color: #856404",
        "Unknown": "background-color: #e2e3e5; color: #383d41",
    }.get(val, "background-color: #f8d7da; color: #721c24")


def style_table(df):
    styler = df.style
    fn = styler.map if hasattr(styler, "map") else styler.applymap
    return fn(color_status, subset=["Deliverability"])


def split_cell(cell):
    return [p.strip() for p in str(cell).split(" * ") if p.strip()]


def process_csv_with_live_output(file, email_column, cfg):
    file.seek(0)
    df = pd.read_csv(file)
    if email_column not in df.columns:
        st.error(f"Column '{email_column}' not found!")
        return None, None, None

    emails = []
    for cell in df[email_column].dropna():
        emails.extend(e.lower() for e in split_cell(cell))
    emails = list(dict.fromkeys(emails))  # unique, original order kept

    start = time.time()
    progress_bar = st.progress(0)
    status_text = st.empty()
    live_table = st.empty()
    tick = {"n": 0}

    def on_progress(rows, done, total):
        tick["n"] += 1
        c = Counter(r["Deliverability"] for r in rows)
        speed = done / max(time.time() - start, 0.001)
        eta = (total - done) / speed if speed > 0 else 0
        status_text.markdown(
            f"**Progress:** {done}/{total}  \n"
            f"Deliverable: **{c['Deliverable']}** | Risky: **{c['Risky']}** | "
            f"Unknown: **{c['Unknown']}** | Not Deliverable: **{c['Not Deliverable']}**  \n"
            f"Speed: **{speed:.1f}** emails/sec | ETA: **{format_time(eta)}**")
        progress_bar.progress(min(done / total, 1.0))
        if tick["n"] % 5 == 0 or done == total:  # redraw table every 5 updates, not every row
            live_table.dataframe(style_table(pd.DataFrame(rows)), use_container_width=True, height=500)

    final = validate_batch(emails, cfg, on_progress)
    val = {r["Email"]: r for r in final}

    # Merge back into the original file (Primary_* and Secondary_* columns, as before)
    primaries, secondaries = [], []
    for cell in df[email_column]:
        parts = [p.lower() for p in split_cell(cell)] if not pd.isna(cell) else []
        primaries.append(parts[0] if parts else "")
        secondaries.append(parts[1] if len(parts) > 1 else "")
    for prefix, col in (("Primary", primaries), ("Secondary", secondaries)):
        df[f"{prefix}_Email"] = col
        for k in FIELDS:
            df[f"{prefix}_{k}"] = [val[e][k] if e in val else "" for e in col]

    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    safe = pd.DataFrame([{"Email": r["Email"]} for r in final if r["Deliverability"] == "Deliverable"])
    return buffer.getvalue(), safe.to_csv(index=False), pd.DataFrame(final)


# ==================== UI ====================

def main():
    st.set_page_config(page_title="Email Validator Pro", layout="centered")
    load_css()
    st.markdown("<p class='h1 h'>Email <span>Validator</span></p>", unsafe_allow_html=True)

    can_smtp = port25_works()
    if can_smtp:
        st.success("Port 25 is open: mailbox checks will run.")
    else:
        st.warning("Port 25 is blocked on this network, so mailboxes cannot be confirmed. "
                   "Results will show **Unknown** instead of guessing. Run the app on a VPS / "
                   "server with port 25 open to get real mailbox checks.")

    with st.expander("Settings", expanded=can_smtp):
        mail_from = st.text_input("Your real sending address (MAIL FROM)", placeholder="you@yourdomain.com",
                                  help="Use an address on your own domain. Fake senders get rejected.")
        helo = st.text_input("Your server hostname (HELO)", value=socket.getfqdn())
        workers = st.slider("Domains checked in parallel", 1, 20, 8)
        delay = st.slider("Seconds between checks on the same domain", 0.0, 5.0, 1.0, 0.5)

    uploaded = st.file_uploader("Choose your CSV file", type=["csv"],
                                help="Multiple emails per cell can be separated by ' * '")

    if uploaded:
        try:
            uploaded.seek(0)
            preview = pd.read_csv(uploaded, nrows=10)
            st.dataframe(preview, use_container_width=True)
            email_column = st.selectbox("Select Email Column", preview.columns.tolist())

            if st.button("Start Validation", type="primary"):
                if can_smtp and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", mail_from or ""):
                    st.error("Enter your real sending address in Settings first.")
                    st.stop()
                cfg = {"skip_smtp": not can_smtp, "mail_from": mail_from, "helo": helo,
                       "workers": workers, "delay": delay, "timeout": 15, "retry_wait": 10}
                with st.spinner("Processing..."):
                    uploaded.seek(0)
                    out_csv, safe_csv, _ = process_csv_with_live_output(uploaded, email_column, cfg)
                if out_csv:
                    st.session_state.output_csv = out_csv
                    st.session_state.safe_csv = safe_csv
                    st.success("Validation Completed!")
        except Exception as e:
            st.error(f"Error: {e}")

    if st.session_state.get("output_csv"):
        st.download_button("Download Full Results CSV", data=st.session_state.output_csv,
                           file_name="validated_results.csv", mime="text/csv", type="primary")
        st.download_button("Download SAFE-TO-SEND list only (Deliverable)", data=st.session_state.safe_csv,
                           file_name="safe_to_send.csv", mime="text/csv")


DISPOSABLE_DOMAINS = fetch_disposable_domains()

if __name__ == "__main__":
    main()
