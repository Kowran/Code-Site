import os
import imaplib
import email
import html
import unicodedata
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(), override=False)

# -----------------------------------------------------------------------------
# Compatibilidade de variáveis (.env)
# Aceita NOVO padrão (EMAIL_HOST/EMAIL_USERNAME/EMAIL_PASSWORD) e ANTIGO (IMAP_HOST/EMAIL/APP_PASSWORD)
# -----------------------------------------------------------------------------
IMAP_HOST = os.environ.get("EMAIL_HOST") or os.environ.get("IMAP_HOST") or ""
IMAP_PORT = int(os.environ.get("EMAIL_PORT", "993"))
IMAP_USER = os.environ.get("EMAIL_USERNAME") or os.environ.get("EMAIL") or ""
IMAP_PASS = os.environ.get("EMAIL_PASSWORD") or os.environ.get("APP_PASSWORD") or ""
IMAP_FOLDER = os.environ.get("EMAIL_FOLDER", "INBOX")

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _normalize_text(s: str) -> str:
    if not s:
        return ""
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch)).lower()

def _decode_subject(msg: Message) -> str:
    raw = msg.get("Subject", "") or ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return raw

def _from_bundle(msg: Message) -> str:
    """Junta nomes e e-mails de From/Sender/Return-Path para checar remetente."""
    fields = []
    for h in ("From", "Sender", "Return-Path"):
        val = msg.get(h, "")
        if not val:
            continue
        try:
            names_emails = getaddresses([val])
            parts = []
            for name, addr in names_emails:
                try:
                    name_dec = str(make_header(decode_header(name))) if name else ""
                except Exception:
                    name_dec = name or ""
                parts.append(f"{name_dec} {addr}".strip())
            fields.append(" ".join(parts))
        except Exception:
            fields.append(val)
    return " ".join(fields)

def _message_date(msg: Message) -> datetime:
    raw = msg.get("Date")
    try:
        dt = email.utils.parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(tz=timezone.utc)

def _html_or_text(msg: Message) -> str:
    """Extrai HTML; se não houver, retorna texto puro escapado."""
    if msg.is_multipart():
        for part in msg.walk():
            ct = (part.get_content_type() or "").lower()
            cd = (part.get("Content-Disposition") or "").lower()
            if ct == "text/html" and "attachment" not in cd:
                try:
                    return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    continue
        for part in msg.walk():
            ct = (part.get_content_type() or "").lower()
            cd = (part.get("Content-Disposition") or "").lower()
            if ct == "text/plain" and "attachment" not in cd:
                try:
                    text_body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                    return f"<pre>{html.escape(text_body)}</pre>"
                except Exception:
                    continue
    else:
        ct = (msg.get_content_type() or "").lower()
        try:
            body = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            body = msg.get_payload()
        if ct == "text/html":
            return body if isinstance(body, str) else str(body)
        return f"<pre>{html.escape(body if isinstance(body, str) else str(body))}</pre>"

    return "<em>(sem conteúdo visualizável)</em>"

def _imap_search_since(imap: imaplib.IMAP4_SSL, since: datetime) -> list[bytes]:
    date_str = since.strftime("%d-%b-%Y")
    typ, data = imap.search(None, "SINCE", date_str)
    if typ != "OK":
        return []
    return data[0].split()

def _connect_select(folder: str) -> imaplib.IMAP4_SSL:
    missing = []
    if not IMAP_HOST: missing.append("EMAIL_HOST/IMAP_HOST")
    if not IMAP_USER: missing.append("EMAIL_USERNAME/EMAIL")
    if not IMAP_PASS: missing.append("EMAIL_PASSWORD/APP_PASSWORD")
    if missing:
        raise RuntimeError("Configuração IMAP ausente: " + ", ".join(missing))
    imap = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    imap.login(IMAP_USER, IMAP_PASS)
    imap.select(folder)
    return imap

# -----------------------------------------------------------------------------
# Função principal
# -----------------------------------------------------------------------------
def fetch_login_code_email_html(
    service: str,
    target_email: str,
    lookback_days: int = 7,
    max_scan: int = 200,
    required_subject_substr: Optional[str] = None,
    required_subject_keywords: Optional[List[str]] = None,
    required_from_contains: Optional[List[str]] = None,      # << NOVO
    forbidden_subject_keywords: Optional[List[str]] = None,  # << NOVO
) -> Optional[str]:
    """
    Retorna HTML do primeiro e-mail que casar com os filtros informados.
    """
    since = datetime.now(tz=timezone.utc) - timedelta(days=lookback_days)

    kw_norm = [_normalize_text(k) for k in (required_subject_keywords or []) if k]
    forbid_norm = [_normalize_text(k) for k in (forbidden_subject_keywords or []) if k]
    from_needles = [_normalize_text(k) for k in (required_from_contains or []) if k]

    imap = _connect_select(IMAP_FOLDER)
    try:
        ids = _imap_search_since(imap, since)
        if not ids:
            return None

        ids = ids[-max_scan:][::-1]  # mais recentes primeiro

        for msg_id in ids:
            typ, data = imap.fetch(msg_id, "(RFC822)")
            if typ != "OK" or not data or not isinstance(data[0], tuple):
                continue

            msg: Message = email.message_from_bytes(data[0][1])

            subject = _decode_subject(msg)
            subject_norm = _normalize_text(subject)

            # 0) Bloqueios explícitos no assunto (ex.: "netflix")
            if forbid_norm and any(k in subject_norm for k in forbid_norm):
                continue

            # 1) Palavras exigidas no assunto (lista) OU substring única
            if kw_norm:
                if not any(k in subject_norm for k in kw_norm):
                    continue
            elif required_subject_substr:
                if _normalize_text(required_subject_substr) not in subject_norm:
                    continue

            # 2) Remetente deve conter certos termos? (ex.: "amazon", "primevideo")
            if from_needles:
                from_bundle = _from_bundle(msg)
                from_norm = _normalize_text(from_bundle)
                if not any(k in from_norm for k in from_needles):
                    continue

            # 3) Janela de tempo
            if _message_date(msg) < since:
                continue

            # 4) Conteúdo
            body_html = _html_or_text(msg)
            dt_str = _message_date(msg).strftime("%d/%m/%Y %H:%M UTC")

            return f"""
            <div>
                <p><strong>Assunto:</strong> {subject}</p>
                <p><strong>Data:</strong> {dt_str}</p>
                <div style="margin-top:10px;border-top:1px solid #ddd;padding-top:10px">
                    {body_html}
                </div>
            </div>
            """

        return None
    finally:
        try:
            imap.close()
        except Exception:
            pass
        try:
            imap.logout()
        except Exception:
            pass
