#python3 -m venv venv
#source venv/bin/activate

pip install -r requirements.txt


export KEYCLOAK_URL="https://cluster.com/auth"
export KEYCLOAK_REALM="maas"
export KEYCLOAK_CLIENT_ID="3scale"
export KEYCLOAK_CLIENT_SECRET=""
export THREESCALE_ADMIN_API_URL="https://cluster.com/admin/api/"
export THREESCALE_ADMIN_API_KEY=""

python mlaas.py