#!/bin/sh

set -euo pipefail

cp /tmp/jwt_public_key/ec_public.key /app/public.pem
cp /tmp/jwt_private_key/ec_private.key /app/private.pem


python manage.py migrate --noinput && python manage.py runserver 0.0.0.0:8000
