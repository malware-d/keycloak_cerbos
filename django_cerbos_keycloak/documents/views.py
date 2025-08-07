from django.http import HttpResponseForbidden, HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from .utils import get_user_roles, get_user_attr
from .utils import extract_roles_and_attrs_from_session, extract_roles_and_attrs_from_jwt
import logging
from .cerbos_client import cerbos_client
from cerbos.sdk.model import Principal, Resource
import json
from datetime import datetime
from .data import DOCUMENT_METADATA

def home(request):
    """Enhanced home view with user context"""
    context = {
        'documents': DOCUMENT_METADATA,
        'current_user': request.user.username if request.user.is_authenticated else None
    }
    if request.user.is_authenticated:
        context['user_roles'] = get_user_roles(request)
    return render(request, 'documents/home.html', context)


logger = logging.getLogger(__name__)
@login_required
def manage_document(request, document_id, action):
    """
    Enhanced document management with complex authorization scenarios.
    Supports multiple document types, statuses, and business rules.
    """
    
    # Get document metadata
    if document_id not in DOCUMENT_METADATA:
        return HttpResponseForbidden("Document not found.")
    
    doc_meta = DOCUMENT_METADATA[document_id]


    roles, attrs = extract_roles_and_attrs_from_session(request)
    if not roles:
        roles, attrs = extract_roles_and_attrs_from_jwt(request)
    logger.info(f"[SESSION] Final roles for user {request.user.username}: {roles}")
    logger.info(f"[SESSION] Final attrs for user {request.user.username}: {attrs}")
    
    # Extract user roles from Keycloak
    user_roles = get_user_roles(request)
    department = get_user_attr(request, "department")
    seniority = get_user_attr(request, "seniority_level")
    project_access = get_user_attr(request, "project_access_level")
    
    if not user_roles:
        print(f"[❌] No roles assigned for user: {request.user.username}")
        return HttpResponseForbidden("No roles assigned. Contact administrator.")
    
    print(f"[🔍] User: {request.user.username}, Roles: {user_roles}, Action: {action}, Document: {document_id}")
    
    # Create Principal with enhanced attributes
    principal = Principal(
        id=request.user.username,
        roles=set(user_roles),
        attr={
            "email": getattr(request.user, 'email', ''),
            "department": department,
            "seniority_level": seniority,
            "project_access_level": project_access
        }
    )
    
    # Create Resource with comprehensive attributes
    resource = Resource(
        id=document_id,
        kind="document",
        attr={
            "author": doc_meta['author'],
            "status": doc_meta['status'],
            "department": doc_meta['department'],
            "classification": doc_meta['classification'],
            "project_budget": doc_meta['project_budget'],
            "content_type": doc_meta['content_type'],
            "created_at": doc_meta['created_at'],
            "title": doc_meta['title'],
            # Additional business context
            "is_financial": doc_meta['department'] == 'Finance',
            "is_sensitive": doc_meta['classification'] in ['confidential', 'restricted'],
            "requires_approval": doc_meta['status'] in ['draft', 'pending_approval'],
            "is_high_value": doc_meta['project_budget'] > 20000
        }
    )
    
    # Check authorization with Cerbos
    try:
        logger.info(f"[CERBOS][CHECK] Principal: {principal}")
        logger.info(f"[CERBOS][CHECK] Resource: {resource}")
        logger.info(f"[CERBOS][CHECK] Action: {action}")
        allowed = cerbos_client.is_allowed(action, principal, resource)
        
        # Log authorization decision
        print(f"[🛡️] Authorization check - User: {request.user.username}, Action: {action}, "
              f"Document: {document_id}, Result: {'ALLOWED' if allowed else 'DENIED'}")
        
        if not allowed:
            # Enhanced error messaging based on context
            error_msg = get_authorization_error_message(action, doc_meta, user_roles, request.user.username)
            return HttpResponseForbidden(error_msg)
            
    except Exception as e:
        print(f"[❌] Cerbos authorization error: {e}")
        return HttpResponseForbidden("Authorization service unavailable. Please try again later.")
    
    # Execute the authorized action
    return execute_document_action(request, document_id, action, doc_meta, principal)


def get_authorization_error_message(action, doc_meta, user_roles, username):
    """Generate contextual error messages"""
    base_msg = f"Access denied for action '{action}' on document '{doc_meta['title']}'."
    
    if action == 'approve' and 'manager' not in user_roles and 'admin' not in user_roles:
        return f"{base_msg} Approval requires manager or admin role."
    
    if action == 'delete' and doc_meta['classification'] == 'confidential' and 'admin' not in user_roles:
        return f"{base_msg} Deleting confidential documents requires admin privileges."
    
    if action in ['view', 'edit'] and doc_meta['author'] != username and 'user' in user_roles and len(user_roles) == 1:
        return f"{base_msg} Users can only {action} their own documents."
    
    if action == 'reject' and doc_meta['status'] != 'pending_approval':
        return f"{base_msg} Can only reject documents with pending approval status."
    
    return f"{base_msg} Insufficient permissions for this operation."

def execute_document_action(request, document_id, action, doc_meta, principal):
    """Execute the authorized document action with realistic responses"""
    
    username = request.user.username
    doc_title = doc_meta['title']
    
    # Simulate action execution with detailed responses
    responses = {
        'view': {
            'title': f'📄 Viewing: {doc_title}',
            'content': f"""
            <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Document Details</h2>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    <p><strong>Title:</strong> {doc_title}</p>
                    <p><strong>Author:</strong> {doc_meta['author']}</p>
                    <p><strong>Department:</strong> {doc_meta['department']}</p>
                    <p><strong>Status:</strong> {doc_meta['status']}</p>
                    <p><strong>Classification:</strong> {doc_meta['classification']}</p>
                    <p><strong>Created:</strong> {doc_meta['created_at']}</p>
                    <p><strong>Budget:</strong> ${doc_meta['project_budget']:,}</p>
                </div>
                <div style="background: #e8f5e8; padding: 15px; border-radius: 5px; border-left: 4px solid #27ae60;">
                    <h3>Content Preview</h3>
                    <p>This is a sample content for {doc_title}. In a real implementation, 
                    this would contain the actual document content based on the document type 
                    and classification level.</p>
                </div>
                <div style="margin-top: 20px;">
                    <a href="/" style="background: #3498db; color: white; padding: 10px 20px; 
                       text-decoration: none; border-radius: 5px;">← Back to Home</a>
                </div>
            </div>
            """,
            'status': 200
        },
        
        'edit': {
            'title': f'✏️ Editing: {doc_title}',
            'content': f"""
            <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Edit Document</h2>
                <form style="background: #f8f9fa; padding: 20px; border-radius: 5px;">
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Title:</label>
                        <input type="text" value="{doc_title}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    </div>
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Status:</label>
                        <select style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                            <option value="{doc_meta['status']}" selected>{doc_meta['status']}</option>
                            <option value="draft">draft</option>
                            <option value="pending_approval">pending_approval</option>
                            <option value="approved">approved</option>
                        </select>
                    </div>
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: bold;">Content:</label>
                        <textarea style="width: 100%; height: 200px; padding: 8px; border: 1px solid #ddd; border-radius: 4px;" 
                                  placeholder="Document content goes here..."></textarea>
                    </div>
                    <button type="submit" style="background: #f39c12; color: white; padding: 10px 20px; 
                            border: none; border-radius: 5px; cursor: pointer;">Save Changes</button>
                    <a href="/" style="background: #95a5a6; color: white; padding: 10px 20px; 
                       text-decoration: none; border-radius: 5px; margin-left: 10px;">Cancel</a>
                </form>
            </div>
            """,
            'status': 200
        },
        
        'delete': {
            'title': f'🗑️ Document Deleted',
            'content': f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 30px; text-align: center;">
                <div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 5px; border-left: 4px solid #dc3545;">
                    <h2>Document Deleted Successfully</h2>
                    <p><strong>"{doc_title}"</strong> has been permanently removed from the system.</p>
                    <p><small>Action performed by: {username} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
                </div>
                <div style="margin-top: 20px;">
                    <a href="/" style="background: #3498db; color: white; padding: 15px 30px; 
                       text-decoration: none; border-radius: 5px;">Return to Home</a>
                </div>
            </div>
            """,
            'status': 200
        },
        
        'approve': {
            'title': f'✅ Document Approved',
            'content': f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 30px; text-align: center;">
                <div style="background: #d4edda; color: #155724; padding: 20px; border-radius: 5px; border-left: 4px solid #28a745;">
                    <h2>Document Approved Successfully</h2>
                    <p><strong>"{doc_title}"</strong> has been approved and is now active.</p>
                    <p><small>Approved by: {username} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
                    <p><small>Department: {doc_meta['department']}</small></p>
                </div>
                <div style="background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    <p><strong>Next Steps:</strong></p>
                    <p>• Document status changed from "{doc_meta['status']}" to "approved"</p>
                    <p>• Stakeholders will be notified via email</p>
                    <p>• Document is now available for public access (if applicable)</p>
                </div>
                <div style="margin-top: 20px;">
                    <a href="/" style="background: #28a745; color: white; padding: 15px 30px; 
                       text-decoration: none; border-radius: 5px;">Return to Home</a>
                </div>
            </div>
            """,
            'status': 200
        },
        
        'reject': {
            'title': f'❌ Document Rejected',
            'content': f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 30px; text-align: center;">
                <div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 5px; border-left: 4px solid #dc3545;">
                    <h2>Document Rejected</h2>
                    <p><strong>"{doc_title}"</strong> has been rejected and requires revision.</p>
                    <p><small>Rejected by: {username} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
                </div>
                <div style="background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    <p><strong>Rejection Reason:</strong></p>
                    <p>Document does not meet the required standards for {doc_meta['department']} department.</p>
                    <p><strong>Required Actions:</strong></p>
                    <p>• Author ({doc_meta['author']}) needs to revise the document</p>
                    <p>• Resubmit for approval once changes are made</p>
                </div>
                <div style="margin-top: 20px;">
                    <a href="/" style="background: #dc3545; color: white; padding: 15px 30px; 
                       text-decoration: none; border-radius: 5px;">Return to Home</a>
                </div>
            </div>
            """,
            'status': 200
        }
    }
    
    if action not in responses:
        return HttpResponseForbidden(f"Invalid action: {action}")
    
    response_data = responses[action]
    return HttpResponse(response_data['content'], status=response_data['status'])

@login_required
@require_http_methods(["GET"])
def user_permissions(request):
    """API endpoint to get current user's permissions for debugging"""
    user_roles = get_user_roles(request)
    
    return JsonResponse({
        'username': request.user.username,
        'roles': list(user_roles) if user_roles else [],
        'department': get_user_attr(request, "department"),
        'seniority_level': get_user_attr(request, "seniority_level"),
        'project_access_level': get_user_attr(request, "project_access_level"),
        'email': getattr(request.user, 'email', ''),
        'timestamp': datetime.now().isoformat()
    })

@login_required
def bulk_document_check(request):
    """Check permissions for multiple documents at once - useful for dashboard"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            document_ids = data.get('document_ids', [])
            actions = data.get('actions', ['view'])
            
            user_roles = get_user_roles(request)
            principal = Principal(
                id=request.user.username,
                roles=set(user_roles),
                attr={
                "department": get_user_attr(request, "department"),
                "seniority_level": get_user_attr(request, "seniority_level"),
                "project_access_level": get_user_attr(request, "project_access_level"),
                "email": getattr(request.user, 'email', ''),
                }
            )
            
            results = {}
            
            for doc_id in document_ids:
                if doc_id not in DOCUMENT_METADATA:
                    continue
                    
                doc_meta = DOCUMENT_METADATA[doc_id]
                resource = Resource(
                    id=doc_id,
                    kind="document",
                    attr={
                    "author": doc_meta['author'],
                    "status": doc_meta['status'],
                    "department": doc_meta['department'],
                    "classification": doc_meta['classification'],
                    "project_budget": doc_meta['project_budget'],
                    "content_type": doc_meta['content_type'],
                    "created_at": doc_meta['created_at'],
                    "title": doc_meta['title'],
                    }
                )
                
                doc_permissions = {}
                for action in actions:
                    try:
                        allowed = cerbos_client.is_allowed(action, principal, resource)
                        doc_permissions[action] = allowed
                    except Exception as e:
                        doc_permissions[action] = False
                        
                results[doc_id] = doc_permissions
            
            return JsonResponse({
                'user': request.user.username,
                'permissions': results,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'POST method required'}, status=405)
            

# from django.http import HttpResponseForbidden, HttpResponse
# from django.shortcuts import render
# from django.contrib.auth.decorators import login_required
# from .utils import get_user_roles
# from .cerbos_client import cerbos_client
# from cerbos.sdk.model import Principal, Resource

# def home(request):
#     return render(request, 'documents/home.html')


# @login_required
# def manage_document(request, document_id, action):
#     """
#     View xử lý kiểm tra quyền truy cập tài liệu dựa trên vai trò người dùng từ Keycloak.
#     Hỗ trợ cả SSO session (social login) lẫn JWT Bearer Token.
#     """

#     # ✅ Trích xuất roles từ session hoặc JWT
#     user_roles = get_user_roles(request)

#     if not user_roles:
#         print("[❌] Không có vai trò nào được gán cho người dùng.")
#         return HttpResponseForbidden("No roles assigned. Please contact administrator.")

#     # ✅ Khởi tạo đối tượng Principal (người dùng)
#     principal = Principal(
#         id=request.user.username,
#         roles=set(user_roles),
#         attr={}  # Có thể thêm attr như email, branch nếu muốn lọc theo điều kiện
#     )

#     # ✅ Khởi tạo đối tượng Resource (tài nguyên cần kiểm tra quyền)
#     resource = Resource(
#         id=document_id,
#         kind="document",
#         attr={
#             "author": request.user.username,
#             "status": "pending_approval",
#             "department": "Marketing"
#         }
#     )

#     # ✅ Gửi yêu cầu kiểm tra tới Cerbos PDP
#     try:
#         allowed = cerbos_client.is_allowed(action, principal, resource)
#         if not allowed:
#             return HttpResponseForbidden(f"Not authorized to {action} this document.")
#     except Exception as e:
#         print(f"[❌] Cerbos error: {e}")
#         return HttpResponseForbidden("Authorization service unavailable.")

#     # ✅ Nếu được phép → thực hiện hành động cụ thể
#     if action == "view":
#         return HttpResponse("Viewing Document: Dummy content.", status=200)
#     elif action == "edit":
#         return HttpResponse("Edit Document: Submit your edits.", status=200)
#     elif action == "delete":
#         return HttpResponse("Document deleted successfully.", status=200)
#     elif action == "approve":
#         return HttpResponse("Document approved successfully.", status=200)
#     else:
#         return HttpResponseForbidden("Invalid action requested.")



