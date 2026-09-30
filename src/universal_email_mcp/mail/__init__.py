"""Mail protocol backends and MIME handling.

- :mod:`.net` — SSRF-safe connections and TLS contexts
- :mod:`.imap` — read-only IMAP session (:class:`~.imap.ImapSession`)
- :mod:`.mime` — header/body parsing, HTML→text, fencing of untrusted content
- :mod:`.folders` — folder-name decoding and role detection
"""
