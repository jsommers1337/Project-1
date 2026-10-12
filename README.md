# Chocolate Lovers Federal Credit Union

A local demo banking portal with registration, sign-in, and a member dashboard showing checking and savings account details.

## Run locally

Python 3.11 or newer is recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:FLASK_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
python app.py
```

Open http://127.0.0.1:5000. On Windows, password hashes are stored with Windows Credential Manager through `keyring`. On Linux, the app uses Python SecretStorage and requires an unlocked Freedesktop Secret Service on the session D-Bus. It will not fall back to plaintext storage.

Account profiles and generated account numbers are stored in `instance/accounts.sqlite3`. Passwords are never stored in SQLite; only salted password hashes are kept in the operating-system credential store. For HTTPS deployments, set `COOKIE_SECURE=1` and provide a stable, private `FLASK_SECRET_KEY`.

## Checks

```powershell
python -m unittest discover -s tests -v
```

This is an educational demo, not a real financial service. Account balances are illustrative, there are no transactions, and the hard-coded routing number is not intended for real use.