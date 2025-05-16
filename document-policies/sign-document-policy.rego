package document.sign

# https://localhost:8181/v1/data/document/sign/allow

# default allow := false

allow if {
	resources := input.resources
	input.path == ["api", "document", resources.documentId, "sign"]
	input.method == "POST"

	# Auth user should be an employee
	input.resources.user.roles[_] == "employee"
}
