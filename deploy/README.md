# Deploying Scrappy OS

This directory holds the systemd unit and the operational reasoning behind it.
Read the reasoning before installing the unit.

## The one rule

**Do not run Scrappy OS as root.**

Scrappy OS proposes operations that were *generated*, not written by a person.
Every containment property in [`docs/SECURITY.md`](../docs/SECURITY.md) assumes
the process is confined by the operating system as well as by its own policy
engine. Running it as root removes the outer layer entirely and leaves you
trusting application code to be perfect. It will not be.

If a task genuinely needs privilege, grant that *one* capability through a
narrowly scoped sudoers rule (below) rather than giving the whole service root.

## 1. Create a service account

A dedicated, unprivileged, non-login account:

```bash
sudo useradd \
  --system \
  --home-dir /var/lib/scrappy-os \
  --create-home \
  --shell /usr/sbin/nologin \
  --comment "Scrappy OS control plane" \
  scrappy

sudo chmod 700 /var/lib/scrappy-os
```

`--shell /usr/sbin/nologin` matters: it means a compromise of the service does
not hand over an interactive shell as this user.

Do **not** add `scrappy` to `sudo`, `wheel`, `docker`, `adm` or `systemd-journal`
as a shortcut. Membership in `docker` in particular is equivalent to root.

## 2. Install the application

```bash
sudo mkdir -p /opt/scrappy-os
sudo chown scrappy:scrappy /opt/scrappy-os
sudo -u scrappy git clone https://github.com/getkcoin-alt/-scrappy-os /opt/scrappy-os
sudo -u scrappy /opt/scrappy-os/scripts/bootstrap.sh
```

The application directory is owned by `scrappy` but is **not** writable at
runtime: `ProtectSystem=strict` in the unit makes the whole filesystem
read-only except for the paths listed in `ReadWritePaths=`. Scrappy OS cannot
modify its own code while running, which is the point.

## 3. Configure

```bash
sudo mkdir -p /etc/scrappy-os
sudo cp /opt/scrappy-os/.env.example /etc/scrappy-os/scrappy.env
sudo chown root:scrappy /etc/scrappy-os/scrappy.env
sudo chmod 640 /etc/scrappy-os/scrappy.env
sudo -e /etc/scrappy-os/scrappy.env
```

`root:scrappy 0640` means the service can read its credentials and cannot
rewrite them. Set at least:

```ini
SCRAPPY_DATA_DIR=/var/lib/scrappy-os
SCRAPPY_WORKSPACE=/var/lib/scrappy-os/workspace
SCRAPPY_MODEL_PROVIDER=ollama       # or openai
SCRAPPY_API_HOST=127.0.0.1          # leave this alone unless you read step 6
```

Never put secrets in `Environment=` lines in the unit file. Those are visible
to any local user through `systemctl show`.

## 4. Install and start the unit

```bash
sudo cp /opt/scrappy-os/deploy/scrappy-os.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scrappy-os

systemctl status scrappy-os
journalctl -u scrappy-os -f
```

Verify from the machine itself:

```bash
curl -s http://127.0.0.1:8787/health | jq
sudo -u scrappy /opt/scrappy-os/.venv/bin/scrappy doctor
```

## 5. Granting a specific privilege, if you must

Scrappy OS runs unprivileged, so `systemctl restart nginx` will fail with a
permission error even after a human approves it. That is the correct default.

If a particular deployment needs one privileged action, grant exactly that
action and nothing more:

```sudoers
# /etc/sudoers.d/scrappy-os  (validate with visudo -c -f)
# Restarting nginx, and only that. No wildcards - `systemctl restart *` would
# let one approved action reach every unit on the machine.
scrappy ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx
scrappy ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx
```

Then add `sudo` to `SCRAPPY_SHELL_ALLOWLIST`. Understand what you have done:
the approval gate is now the only thing between a generated plan and that
command. Keep the sudoers list short enough to read in one screen, and audit it
the way you would audit any other privilege grant.

## 6. Exposing the API (and why you probably should not)

The API has **no authentication**. It binds to `127.0.0.1` and the unit denies
outbound IP traffic by default.

If a remote operator needs access, terminate authentication in front of it -
an SSH tunnel is the simplest correct answer:

```bash
ssh -N -L 8787:127.0.0.1:8787 operator@server
```

For anything more permanent, put an authenticating reverse proxy (mTLS, OIDC,
whatever your organisation already runs) in front, keep Scrappy OS bound to
loopback, and never set `SCRAPPY_API_HOST=0.0.0.0`. `scrappy doctor` reports a
non-local bind as a warning for exactly this reason.

## 7. Ongoing operation

```bash
# What has it been doing?
sudo -u scrappy /opt/scrappy-os/.venv/bin/scrappy audit --limit 50

# What is waiting on a human?
sudo -u scrappy /opt/scrappy-os/.venv/bin/scrappy approvals

# Structured logs
journalctl -u scrappy-os -o json-pretty | jq 'select(.MESSAGE | contains("security.denied"))'
```

Back up `/var/lib/scrappy-os/scrappy.db`. It is the audit trail, and it is the
only durable record of what this machine was asked to do.

## Upgrading

```bash
sudo systemctl stop scrappy-os
sudo -u scrappy git -C /opt/scrappy-os pull
sudo -u scrappy /opt/scrappy-os/.venv/bin/pip install -e /opt/scrappy-os
sudo -u scrappy /opt/scrappy-os/.venv/bin/scrappy doctor
sudo systemctl start scrappy-os
```

The database schema is created and migrated on connect; stopping the service
first lets the WAL checkpoint cleanly.

## Uninstalling

```bash
sudo systemctl disable --now scrappy-os
sudo rm /etc/systemd/system/scrappy-os.service
sudo systemctl daemon-reload
sudo rm -rf /opt/scrappy-os /etc/scrappy-os
# Keep /var/lib/scrappy-os if you want to retain the audit trail.
sudo userdel scrappy
```
