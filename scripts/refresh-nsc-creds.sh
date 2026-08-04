#!/usr/bin/env bash
# Refresh the [nsc-swarm] profile with fresh temporary credentials for
# account 865679935554, by assuming OrganizationAccountAccessRole from the
# [default] profile (188494237500).
#
# Why this exists: the nsc-swarm profile holds STS temporary credentials
# (ASIA...) which expire. When they lapse, every AWS call either 403s or
# silently falls back to the WRONG account (188494237500).
#
# Usage:  bash scripts/refresh-nsc-creds.sh
# Then:   export AWS_PROFILE=nsc-swarm
set -euo pipefail

ROLE_ARN="arn:aws:iam::865679935554:role/OrganizationAccountAccessRole"
DURATION="${DURATION:-3600}"

echo "Assuming ${ROLE_ARN} ..."
CREDS_JSON="$(aws sts assume-role \
  --profile default \
  --role-arn "${ROLE_ARN}" \
  --role-session-name "refresh-$(date +%s)" \
  --duration-seconds "${DURATION}" \
  --output json)"

python3 - "$CREDS_JSON" <<'PY'
import sys, json, configparser, os
c = json.loads(sys.argv[1])["Credentials"]
p = os.path.expanduser("~/.aws/credentials")
cfg = configparser.ConfigParser(); cfg.read(p)
if "nsc-swarm" not in cfg:
    cfg["nsc-swarm"] = {}
cfg["nsc-swarm"]["aws_access_key_id"]     = c["AccessKeyId"]
cfg["nsc-swarm"]["aws_secret_access_key"] = c["SecretAccessKey"]
cfg["nsc-swarm"]["aws_session_token"]     = c["SessionToken"]
with open(p, "w") as f:
    cfg.write(f)
os.chmod(p, 0o600)
print("[nsc-swarm] refreshed, expires", c["Expiration"])
PY

echo "Verifying ..."
ACCT="$(AWS_PROFILE=nsc-swarm aws sts get-caller-identity --query Account --output text)"
if [ "${ACCT}" != "865679935554" ]; then
  echo "FAILED: resolved account ${ACCT}, expected 865679935554" >&2
  exit 1
fi
echo "OK: authenticated to ${ACCT} (nsc-swarm)"
echo
echo "Remember:  export AWS_PROFILE=nsc-swarm"
echo "NEVER pin these into keys/.env — swarm_auth's AccessScript triage reads"
echo "dotenv before the profile chain and would serve them long after expiry."
