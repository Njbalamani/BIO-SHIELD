# Deployment

This guide covers local development, container deployment and production hardening for BioShield. All instructions assume the repository root is `BioShield`.

## Local development

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

Linux equivalent:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

Edit `.env` before first run. Keep `DEBUG=False` and `SYNTHETIC_DATA_ONLY=True`.

## Container deployment

```powershell
docker compose -f docker/docker-compose.yml --env-file .env up --build -d
docker compose -f docker/docker-compose.yml exec web python manage.py migrate
docker compose -f docker/docker-compose.yml exec web python manage.py collectstatic --noinput
docker compose -f docker/docker-compose.yml exec web python manage.py createsuperuser
```

Services:

| Service | Image / command | Purpose |
| --- | --- | --- |
| `db` | PostgreSQL 16 | Application database with healthcheck |
| `redis` | Redis 7 Alpine | Celery broker and cache |
| `web` | Custom Python image + Gunicorn | Django application |
| `celery` | Custom Python image + Celery worker | Scan and report tasks |
| `nginx` | Nginx 1.27 Alpine | Reverse proxy and static assets |

The compose stack does not mount the Docker socket and does not grant privileged mode. Named volumes hold database state, static files and media.

## Required environment

| Variable | Production guidance |
| --- | --- |
| `SECRET_KEY` | Generate a unique random value; never commit it |
| `DEBUG` | `False` |
| `ALLOWED_HOSTS` | Explicit comma-separated hostnames |
| `DB_*` | Strong password and non-default database name |
| `REDIS_URL` | Internal `redis://redis:6379/0` URL |
| `CELERY_TASK_ALWAYS_EAGER` | `False` |
| `SECURE_SSL_REDIRECT` | `True` when TLS terminates correctly |
| `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` | `True` behind HTTPS |
| `SECURE_HSTS_SECONDS` | Start low and increase after verification |
| `CONTENT_SECURITY_POLICY` | Must include app origin plus CDN hosts used for Three.js, GSAP and Chart.js |
| `FIELD_ENCRYPTION_KEY` | Valid Fernet key stored in a secret manager |
| `SYNTHETIC_DATA_ONLY` | `True` for this demonstration deployment |

## Static assets

`collectstatic` writes to `staticfiles/`, mounted to Nginx at `/static/`. WhiteNoise is available as an alternative static backend. CDN assets are fetched by the browser from `cdnjs.cloudflare.com` and `cdn.jsdelivr.net`; update the CSP if you self-host them.

## Health checks

- `GET /health/live/` returns 200 when the process is running.
- `GET /health/ready/` returns 503 if the database query fails.
- Compose healthchecks gate `web` and `nginx` startup.

## TLS

Terminate TLS at the load balancer or Nginx. Redirect HTTP to HTTPS, enable HSTS only after confirming all subdomains are ready, and keep secure cookie flags enabled. Do not expose PostgreSQL or Redis ports publicly.

## Backup and restore

```powershell
docker compose -f docker/docker-compose.yml exec db pg_dump -U bioshield bioshield > bioshield-backup.sql
docker compose -f docker/docker-compose.yml exec -T db psql -U bioshield bioshield < bioshield-backup.sql
```

Backups contain synthetic demonstration data only, but protect credentials and secrets regardless.

## Operational checks

```powershell
docker compose -f docker/docker-compose.yml ps
docker compose -f docker/docker-compose.yml logs --tail=200 web celery nginx
docker compose -f docker/docker-compose.yml exec web python manage.py check
docker compose -f docker/docker-compose.yml exec web python manage.py check --deploy
```

Blue-green or rolling deploys should drain Celery tasks before replacing workers and run migrations as a separate step. See `docs/security.md` before exposing the service beyond a trusted demo audience.
