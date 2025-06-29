#python3 -m venv venv
#source venv/bin/activate

pip install -r requirements.txt


export KEYCLOAK_URL="https://keycloak-rh-sso.apps.cluster-qlzvh.qlzvh.sandbox205.opentlc.com/auth"
export KEYCLOAK_REALM="maas"
export KEYCLOAK_CLIENT_ID="3scale"
export KEYCLOAK_CLIENT_SECRET="pYqs2K0ccRkHFfToKSfkOCKPJugfah0O"
export THREESCALE_ADMIN_API_URL="https://maas-admin.apps.cluster-qlzvh.qlzvh.sandbox205.opentlc.com/admin/api/"
export THREESCALE_ADMIN_API_KEY="c0fd0141f4772fb87d49a44c156fbfe9ddab5bb18ce3fcb968f2543e543f9a79"

python mlaas.py