# utils.py - Chuẩn production: Chỉ trả ra data, không log

from jose import jwt
from django.conf import settings

KEYCLOAK_ATTRS = [
    "department",
    "seniority_level",
    "project_access_level",
    # Thêm attr tuỳ chỉnh nếu cần!
]

EXCLUDED_ROLES = [
    'default-roles-django-app', 'offline_access', 'uma_authorization'
]

def extract_roles_and_attrs_from_session(request):
    """
    Trả về tuple: (roles, attrs) từ session OIDC (django-allauth/socialaccount.extra_data)
    """
    if hasattr(request.user, 'socialaccount_set'):
        accounts = request.user.socialaccount_set.all()
        if accounts:
            extra_data = accounts[0].extra_data

            # Lấy roles
            roles = []
            if 'realm_access' in extra_data:
                roles.extend(extra_data['realm_access'].get('roles', []))
            if 'resource_access' in extra_data:
                for client_data in extra_data['resource_access'].values():
                    roles.extend(client_data.get('roles', []))
            unique_roles = list(set(roles))
            filtered_roles = [r for r in unique_roles if r not in EXCLUDED_ROLES]

            # Lấy attrs
            attrs = {attr: extra_data.get(attr) for attr in KEYCLOAK_ATTRS}
            return filtered_roles, attrs
    return [], {}

def extract_roles_and_attrs_from_jwt(request):
    """
    Trả về tuple: (roles, attrs) từ JWT (Authorization Bearer token)
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return [], {}
    token = auth_header.split()[1]
    try:
        public_key = settings.KEYCLOAK_PUBLIC_KEY.strip().replace('\\n', '\n')
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])
        roles = decoded_token.get('realm_access', {}).get('roles', [])
        if 'resource_access' in decoded_token:
            for client_data in decoded_token['resource_access'].values():
                roles.extend(client_data.get('roles', []))
        unique_roles = list(set(roles))
        filtered_roles = [r for r in unique_roles if r not in EXCLUDED_ROLES]
        attrs = {attr: decoded_token.get(attr) for attr in KEYCLOAK_ATTRS}
        return filtered_roles, attrs
    except Exception:
        return [], {}

def get_user_roles(request):
    """
    Trả về list roles (ưu tiên session, fallback JWT)
    """
    roles, _ = extract_roles_and_attrs_from_session(request)
    if roles:
        return roles
    roles, _ = extract_roles_and_attrs_from_jwt(request)
    return roles

def get_user_attr(request, attr_name, default="empty"):
    """
    Trả về giá trị attr (ưu tiên session, fallback JWT, cuối cùng default)
    """
    _, attrs = extract_roles_and_attrs_from_session(request)
    if attrs and attr_name in attrs and attrs[attr_name]:
        return attrs[attr_name]
    _, attrs = extract_roles_and_attrs_from_jwt(request)
    if attrs and attr_name in attrs and attrs[attr_name]:
        return attrs[attr_name]
    return default


# # utils.py - Chuẩn production: lấy roles & attributes động từ OIDC/Keycloak
# from jose import jwt
# from django.conf import settings
# import logging

# logger = logging.getLogger(__name__)

# KEYCLOAK_ATTRS = [
#     "department",
#     "seniority_level",
#     "project_access_level",
#     # Nếu bạn có thêm attr tuỳ chỉnh khác, thêm tại đây!
# ]

# EXCLUDED_ROLES = [
#     'default-roles-django-app', 'offline_access', 'uma_authorization'
# ]


# def extract_roles_and_attrs_from_jwt(request):
#     """
#     Trích xuất roles và các attributes tùy chỉnh từ JWT (dùng cho API/Bearer Token).
#     """
#     auth_header = request.headers.get('Authorization')
#     if not auth_header or not auth_header.startswith('Bearer '):
#         logger.debug("No Bearer token found in Authorization header.")
#         return [], {}

#     token = auth_header.split()[1]
#     try:
#         public_key = settings.KEYCLOAK_PUBLIC_KEY.strip().replace('\\n', '\n')
#         decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])

#         # Lấy roles
#         roles = decoded_token.get('realm_access', {}).get('roles', [])
#         if 'resource_access' in decoded_token:
#             for client_data in decoded_token['resource_access'].values():
#                 roles.extend(client_data.get('roles', []))
#         # Lọc duplicate và loại bỏ role rác
#         unique_roles = list(set(roles))
#         filtered_roles = [
#             r for r in unique_roles if r not in EXCLUDED_ROLES
#         ]

#         # Lấy các attributes mở rộng
#         attrs = {}
#         for attr in KEYCLOAK_ATTRS:
#             attrs[attr] = decoded_token.get(attr)

#         logger.info(f"[JWT] Extracted roles: {filtered_roles}")
#         logger.info(f"[JWT] Extracted attrs: {attrs}")

#         return filtered_roles, attrs

#     except Exception as e:
#         logger.error(f"[JWT] Error decoding JWT: {str(e)}")
#         return [], {}


# def extract_roles_and_attrs_from_session(request):
#     """
#     Trích xuất roles & attr từ session OIDC (django-allauth/socialaccount.extra_data).
#     """
#     try:
#         if hasattr(request.user, 'socialaccount_set'):
#             accounts = request.user.socialaccount_set.all()
#             if accounts:
#                 extra_data = accounts[0].extra_data
#                 logger.info(f"[SESSION] Extra data: {extra_data}")

#                 # Lấy roles
#                 roles = []
#                 if 'realm_access' in extra_data:
#                     roles.extend(extra_data['realm_access'].get('roles', []))
#                 if 'resource_access' in extra_data:
#                     for client_data in extra_data['resource_access'].values():
#                         roles.extend(client_data.get('roles', []))
#                 unique_roles = list(set(roles))
#                 filtered_roles = [
#                     r for r in unique_roles if r not in EXCLUDED_ROLES
#                 ]

#                 # Lấy attributes động (tuỳ chỉnh)
#                 attrs = {}
#                 for attr in KEYCLOAK_ATTRS:
#                     attrs[attr] = extra_data.get(attr)

#                 logger.info(f"[SESSION] Extracted roles: {filtered_roles}")
#                 logger.info(f"[SESSION] Extracted attrs: {attrs}")
#                 return filtered_roles, attrs

#         logger.warning("[SESSION] No roles found in session.")
#         return [], {}

#     except Exception as e:
#         logger.error(f"[SESSION] Error getting roles/attrs from session: {str(e)}")
#         return [], {}


# def get_user_roles(request):
#     """
#     Trả về danh sách roles thực tế (ưu tiên session, fallback JWT).
#     """
#     roles, _ = extract_roles_and_attrs_from_session(request)
#     if roles:
#         return roles
#     logger.info("Falling back to JWT-based role extraction.")
#     roles, _ = extract_roles_and_attrs_from_jwt(request)
#     return roles


# def get_user_attr(request, attr_name, default="None"):
#     """
#     Trả về giá trị attribute Keycloak (ví dụ: department, seniority_level...)  
#     (ưu tiên lấy từ session, không có thì lấy từ JWT, cuối cùng trả về default)
#     """
#     # Ưu tiên session
#     _, attrs = extract_roles_and_attrs_from_session(request)
#     if attrs and attr_name in attrs and attrs[attr_name]:
#         return attrs[attr_name]
#     # Fallback qua JWT
#     _, attrs = extract_roles_and_attrs_from_jwt(request)
#     if attrs and attr_name in attrs and attrs[attr_name]:
#         return attrs[attr_name]
#     return default



# from jose import jwt
# from django.conf import settings
# import logging

# logger = logging.getLogger(__name__)

# def extract_roles_from_jwt(request):
#     """
#     Extract roles from JWT in Authorization header (Bearer token).
#     This is for API-based authentication (e.g., mobile, SPA).
#     """
#     auth_header = request.headers.get('Authorization')
#     if not auth_header or not auth_header.startswith('Bearer '):
#         logger.debug("No Bearer token found in Authorization header.")
#         return []

#     token = auth_header.split()[1]
#     try:
#         # # For production, use Keycloak public key and verify signature
#         # decoded_token = jwt.decode(token, options={"verify_signature": False})
#         public_key = settings.KEYCLOAK_PUBLIC_KEY.strip().replace('\\n', '\n')

#         decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])

#         # Extract roles from realm_access
#         roles = decoded_token.get('realm_access', {}).get('roles', [])

#         # Also check for resource_access.<client>.roles if needed
#         if 'resource_access' in decoded_token:
#             for client_data in decoded_token['resource_access'].values():
#                 roles.extend(client_data.get('roles', []))

#         # Remove duplicates and filter unwanted default roles
#         unique_roles = list(set(roles))
#         filtered_roles = [
#             r for r in unique_roles
#             if r not in ['default-roles-django-app', 'offline_access', 'uma_authorization']
#         ]

#         logger.info(f"[JWT] Extracted roles: {filtered_roles}")
        
#         return filtered_roles

#     except Exception as e:
#         logger.error(f"[JWT] Error decoding JWT: {str(e)}")
#         return []

# def extract_roles_from_session(request):
#     """
#     Extract roles from Keycloak session via django-allauth (socialaccount.extra_data).
#     """
#     try:
#         if hasattr(request.user, 'socialaccount_set'):
#             accounts = request.user.socialaccount_set.all()
#             if accounts:
#                 extra_data = accounts[0].extra_data
#                 logger.info(f"[SESSION] Extra data: {extra_data}")

#                 roles = []

#                 # Path 1: realm_access.roles
#                 if 'realm_access' in extra_data:
#                     roles.extend(extra_data['realm_access'].get('roles', []))

#                 # Path 2: resource_access.<client_id>.roles
#                 if 'resource_access' in extra_data:
#                     for client_data in extra_data['resource_access'].values():
#                         roles.extend(client_data.get('roles', []))

#                 # Remove duplicates and filter default roles
#                 unique_roles = list(set(roles))
#                 filtered_roles = [
#                     r for r in unique_roles
#                     if r not in ['default-roles-django-app', 'offline_access', 'uma_authorization']
#                 ]

#                 logger.info(f"[SESSION] Extracted roles: {filtered_roles}")


#                 return filtered_roles

#         logger.warning("[SESSION] No roles found in session.")
#         return []

#     except Exception as e:
#         logger.error(f"[SESSION] Error getting roles from session: {str(e)}")
#         return []

# def get_user_roles(request):
#     """
#     Try to get user roles from session first, fallback to JWT if necessary.
#     """
#     roles = extract_roles_from_session(request)
#     if roles:
#         return roles

#     logger.info("Falling back to JWT-based role extraction.")
#     return extract_roles_from_jwt(request)



