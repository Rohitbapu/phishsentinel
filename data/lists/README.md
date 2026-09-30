# Tier 0 lists (drop files here, no code edits needed)

| File | What goes in it |
|---|---|
| `known_bad*.txt` / `.csv` | Domains or URLs of known phishing. Raw feeds work as they are (OpenPhish text, PhishTank CSV). Several files are merged. |
| `allow*.txt` | Domains YOUR ORGANISATION trusts. Keep it small and vetted; an allow-list hit + DMARC pass auto-releases mail. |
| `brands.json` | `{"acmebank": ["acmebank.com"]}` extends the look-alike brand map. |

Safety guards built in: URLs on shared platforms (github.io, blogspot.com, sites.google.com ...), real brand domains and
allow-listed domains are never added to the block list. `GET /health` shows how many entries loaded and how many were skipped.
Check each feed's licence before use and cite it. Restart the server after changing files.
