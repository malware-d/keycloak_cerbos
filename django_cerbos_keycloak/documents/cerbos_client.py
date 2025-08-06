# cerbos_client.py
from cerbos.sdk.client import CerbosClient

# HTTP endpoint của Cerbos PDP
# Theo conf.yaml, Cerbos HTTP lắng nghe ở port 3592
CERBOS_HOST = "http://localhost:3592"

# Khởi tạo HTTP-client, tắt verify TLS (nếu dùng HTTPS)
cerbos_client = CerbosClient(host=CERBOS_HOST, tls_verify=False)