#python3 -m venv venv
#source venv/bin/activate

pip install -r requirements.txt

echo | openssl s_client -showcerts -servername your-keycloak-instance.com -connect your-keycloak-instance.com:443 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > keycloak_cert_bundle.pem

export REQUESTS_CA_BUNDLE=/path/to/your/ca-cert.pem

export KEYCLOAK_URL="https://cluster.com/auth"
export KEYCLOAK_REALM="maas"
export KEYCLOAK_CLIENT_ID="3scale"
export KEYCLOAK_CLIENT_SECRET=""
export THREESCALE_ADMIN_API_URL="https://cluster.com/admin/api/"
export THREESCALE_ADMIN_API_KEY=""

python mlaas.py
