package document.sign

import data.utils.role.get_user_roles


# https://localhost:8181/v1/data/document/sign/allow

default allow = false

allow if {
    resources := input.resources

    input.path   == ["document", input.documentId, "sign"]
    input.method == "POST"

    # 3. Auth user must be an employee
    some i
    resources.user.roles[i] == "employee"
}
