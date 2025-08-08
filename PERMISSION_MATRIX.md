# PERMISSION MATRIX - MA TRẬN PHÂN QUYỀN

Bảng tổng hợp quyền truy cập từ tất cả policies (Documents ở hàng dọc, Principals theo group ở hàng ngang).

**Ký hiệu:**
- ✅ = ALLOW (có quyền)
- ❌ = DENY (bị từ chối) 
- ➖ = Không có rule (mặc định DENY)
- 🔄 = Có điều kiện (phụ thuộc context)

**Format mỗi ô:** `V/E/A/R/D` (View/Edit/Approve/Reject/Delete)

## MA TRẬN TỔNG HỢP

| Document / Principal | **SYSTEM ROLES** |  |  | **DEPARTMENT MANAGERS** |  |  | **SPECIAL PRINCIPALS** |  |  |  |  |  |
|---------------------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|---------|
|                     | **admin** | **manager<br/>(Marketing)** | **manager<br/>(Finance)** | **manager<br/>(HR)** | **reviewer** | **user<br/>(Marketing)** | **user<br/>(Finance)** | **finance_manager** | **project_manager** | **external_consultant** | **security_auditor** | **john_doe** | **intern_user** |
| **doc_marketing_001**<br/>*Marketing Campaign Plan*<br/>*(Marketing, internal, pending_approval, 50K, john_doe)* | ✅/✅/✅/✅/✅<br/>*admin_full* | ✅/✅/❌/✅/➖<br/>*dept_access,<br/>high_value_deny* | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ✅/✅/❌/✅/➖<br/>*approval_workflow,<br/>high_value_deny* | ✅/✅/➖/➖/➖<br/>*dept_docs,<br/>own_docs* | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ✅/✅/❌/➖/➖<br/>*cross_dept,<br/>edit_budget* | ❌/❌/➖/➖/➖<br/>*view_assigned_deny* | ✅/➖/➖/➖/➖<br/>*view_all* | ✅/✅/❌/➖/➖<br/>*marketing_docs,<br/>own_docs* | ❌/❌/➖/➖/➖<br/>*budget>5K_deny* |
| **doc_finance_001**<br/>*Q4 Budget Report*<br/>*(Finance, confidential, approved, 1M, finance_user)* | ✅/✅/✅/✅/✅<br/>*admin_full* | ➖/➖/➖/➖/➖ | ✅/❌/✅/✅/➖<br/>*dept_access,<br/>no_edit_approved* | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ❌/➖/➖/➖/➖<br/>*confidential_deny* | 🔄/❌/➖/➖/➖<br/>*own_docs?,<br/>approved_deny* | ✅/✅/✅/✅/❌<br/>*finance_dept* | ➖/➖/➖/➖/➖ | ❌/➖/➖/➖/➖<br/>*deny_internal* | ✅/➖/➖/✅/➖<br/>*view_all,<br/>reject_violations* | ❌/➖/➖/➖/➖<br/>*confidential_deny* | ❌/➖/➖/➖/➖<br/>*confidential_deny* |
| **doc_hr_001**<br/>*Employee Handbook*<br/>*(HR, internal, draft, 10K, hr_manager)* | ✅/✅/✅/✅/✅<br/>*admin_full* | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ✅/✅/✅/✅/✅<br/>*dept_access,<br/>cleanup_drafts* | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ✅/✅/✅/➖/➖<br/>*cross_dept,<br/>edit_budget,<br/>approve_low* | ❌/➖/➖/➖/➖<br/>*deny_internal* | ✅/➖/➖/➖/➖<br/>*view_all* | ➖/➖/➖/➖/➖ | ❌/➖/➖/➖/➖<br/>*budget>5K_deny* |
| **doc_it_001**<br/>*Security Policy*<br/>*(IT, confidential, rejected, 25K, it_admin)* | ✅/✅/✅/✅/✅<br/>*admin_full* | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ✅/❌/➖/➖/➖<br/>*cross_dept,<br/>edit_status* | ❌/➖/➖/➖/➖<br/>*deny_internal* | ✅/✅/✅/✅/➖<br/>*view_all,<br/>security_policy* | ➖/➖/➖/➖/➖ | ❌/➖/➖/➖/➖<br/>*confidential_deny* |
| **doc_marketing_002**<br/>*Brand Guidelines*<br/>*(Marketing, public, approved, 1.5K, jane_smith)* | ✅/✅/✅/✅/✅<br/>*admin_full* | ✅/❌/✅/✅/➖<br/>*dept_access,<br/>no_edit_approved* | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ➖/➖/➖/➖/➖ | ✅/➖/➖/➖/➖<br/>*public_approved* | ✅/➖/➖/➖/➖<br/>*public_approved* | ➖/➖/➖/➖/➖ | ✅/❌/✅/➖/➖<br/>*cross_dept,<br/>edit_status,<br/>approve_low* | ✅/❌/➖/➖/➖<br/>*view_assigned,<br/>edit_own_deny* | ✅/➖/➖/➖/➖<br/>*view_all* | ✅/✅/➖/➖/➖<br/>*marketing_docs,<br/>brand_docs* | ✅/❌/➖/➖/➖<br/>*public_approved,<br/>edit_own_deny* |
| **doc_finance_002**<br/>*Expense Report*<br/>*(Finance, restricted, pending_review, 5K, john_finance)* | ✅/✅/✅/✅/✅<br/>*admin_full* | ➖/➖/➖/➖/➖ | ✅/✅/✅/✅/➖<br/>*dept_access* | ➖/➖/➖/➖/➖ | ❌/❌/✅/✅/➖<br/>*approval_workflow,<br/>restricted_deny* | ❌/❌/➖/➖/➖<br/>*restricted_deny* | ❌/❌/➖/➖/➖<br/>*restricted_deny* | ✅/✅/✅/✅/❌<br/>*finance_dept* | ➖/➖/➖/➖/➖ | ❌/➖/➖/➖/➖<br/>*deny_internal* | ✅/➖/➖/✅/➖<br/>*view_all,<br/>reject_violations* | ❌/❌/➖/➖/➖<br/>*restricted_deny* | ❌/➖/➖/➖/➖<br/>*budget>5K_deny* |

## CHI TIẾT PRINCIPALS

### SYSTEM ROLES
- **admin**: Full system access
- **manager (dept)**: Department-based management
- **reviewer**: Document approval workflow
- **user (dept)**: Basic user in specific department

### SPECIAL PRINCIPALS  
- **finance_manager**: Finance department specialist
- **project_manager**: Cross-department project coordination
- **external_consultant**: Limited external access
- **security_auditor**: Read-only + security approvals
- **john_doe**: Marketing user with special brand permissions
- **intern_user**: Limited intern with budget restrictions

## RULES THAM CHIẾU

- **admin_full**: Admin có tất cả quyền
- **dept_access**: Manager có quyền trong department của mình
- **high_value_deny**: DENY approve nếu budget > 50K và không phải executive
- **approval_workflow**: Reviewer có quyền view/approve/reject với status pending
- **confidential_deny**: User DENY view confidential nếu không phải author
- **restricted_deny**: User/reviewer DENY view/edit restricted nếu không có all_projects
- **no_edit_approved**: DENY edit nếu status = approved
- **public_approved**: User có thể view public + approved
- **own_docs**: User có thể view/edit tài liệu của mình
- **budget>5K_deny**: intern_user DENY nếu budget > 5000
- **cross_dept**: project_manager có thể view cross departments
- **security_policy**: Đặc biệt cho security_auditor với security documents
- **finance_dept**: finance_manager có quyền đầy đủ trong Finance dept

---

Ma trận này tổ chức theo Documents (dọc) x Principals được group (ngang) để dễ so sánh quyền truy cập.