package document.sign
import future.keywords.http

# https://localhost:8181/v1/data/document/sign/allow

default allow = false

allow if {
	input.path == ["api", "document", resources.documentId, "sign"]
	input.method == "POST"

    # Fetch the policy‐data from the Express endpoint
    resp := http.send({
        "method": "GET",
        "url": sprintf(
          "http://localhost:3000/api/policy-data/documents/%s?userId=%s",
          [doc_id, input.userId]
        )
    })
    resources := resp.body

	# Auth user should be an employee
	resources.user.roles[_] == "employee"
}
