package document.sign

import data.utils.role.get_user_roles


# https://localhost:8181/v1/data/document/sign/allow

default allow = false

allow if {

    # Fetch the policy‐data from the Express endpoint
    resp := http.send({
        "method": "GET",
        "url": sprintf(
          "http://localhost:3000/api/policy-data/documents/%s?userId=%s",
          [input.documentId, input.userId]
        )
    })
    resources := resp.body

    # 2. Match path & method
    input.path   == ["document", input.documentId, "sign"]
    input.method == "POST"

    # 3. Auth user must be an employee
    some i
    resources.user.roles[i] == "employee"
}
