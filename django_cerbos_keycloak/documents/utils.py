
from jose import jwt
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def extract_roles_from_jwt(request):
    """
    Extract roles from JWT in Authorization header (Bearer token).
    This is for API-based authentication (e.g., mobile, SPA).
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.debug("No Bearer token found in Authorization header.")
        return []

    token = auth_header.split()[1]
    try:
        # # For production, use Keycloak public key and verify signature
        # decoded_token = jwt.decode(token, options={"verify_signature": False})
        public_key = settings.KEYCLOAK_PUBLIC_KEY.strip().replace('\\n', '\n')

        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"])

        # Extract roles from realm_access
        roles = decoded_token.get('realm_access', {}).get('roles', [])

        # Also check for resource_access.<client>.roles if needed
        if 'resource_access' in decoded_token:
            for client_data in decoded_token['resource_access'].values():
                roles.extend(client_data.get('roles', []))

        # Remove duplicates and filter unwanted default roles
        unique_roles = list(set(roles))
        filtered_roles = [
            r for r in unique_roles
            if r not in ['default-roles-django-app', 'offline_access', 'uma_authorization']
        ]

        logger.info(f"[JWT] Extracted roles: {filtered_roles}")
        return filtered_roles

    except Exception as e:
        logger.error(f"[JWT] Error decoding JWT: {str(e)}")
        return []

def extract_roles_from_session(request):
    """
    Extract roles from Keycloak session via django-allauth (socialaccount.extra_data).
    """
    try:
        if hasattr(request.user, 'socialaccount_set'):
            accounts = request.user.socialaccount_set.all()
            if accounts:
                extra_data = accounts[0].extra_data
                logger.info(f"[SESSION] Extra data: {extra_data}")

                roles = []

                # Path 1: realm_access.roles
                if 'realm_access' in extra_data:
                    roles.extend(extra_data['realm_access'].get('roles', []))

                # Path 2: resource_access.<client_id>.roles
                if 'resource_access' in extra_data:
                    for client_data in extra_data['resource_access'].values():
                        roles.extend(client_data.get('roles', []))

                # Remove duplicates and filter default roles
                unique_roles = list(set(roles))
                filtered_roles = [
                    r for r in unique_roles
                    if r not in ['default-roles-django-app', 'offline_access', 'uma_authorization']
                ]

                logger.info(f"[SESSION] Extracted roles: {filtered_roles}")
                return filtered_roles

        logger.warning("[SESSION] No roles found in session.")
        return []

    except Exception as e:
        logger.error(f"[SESSION] Error getting roles from session: {str(e)}")
        return []

def get_user_roles(request):
    """
    Try to get user roles from session first, fallback to JWT if necessary.
    """
    roles = extract_roles_from_session(request)
    if roles:
        return roles

    logger.info("Falling back to JWT-based role extraction.")
    return extract_roles_from_jwt(request)



