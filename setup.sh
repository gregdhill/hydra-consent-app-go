#!/bin/bash

# run hydra
docker run -it --rm --name login-consent-hydra -d -p 4444:4444 -p 4445:4445 \
    -e OAUTH2_SHARE_ERROR_DEBUG=1 \
    -e LOG_LEVEL=debug \
    -e OAUTH2_CONSENT_URL=http://localhost:3000/consent \
    -e OAUTH2_LOGIN_URL=http://localhost:3000/login \
    -e OAUTH2_ISSUER_URL=http://localhost:4444 \
    -e DATABASE_URL=memory \
    oryd/hydra:latest serve all --dangerous-force-http

# wait for hydra to start
sleep 5

# add our oauth2 client
docker run --link login-consent-hydra:hydra oryd/hydra:latest clients create \
    --endpoint http://hydra:4445 \
    --id test-client \
    --secret test-secret \
    --response-types code,id_token \
    --token-endpoint-auth-method client_secret_post \
    --grant-types refresh_token,authorization_code,client_credentials \
    --scope openid,offline \
    --callbacks http://localhost:3000/callback