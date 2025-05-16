package document.upload

# https://localhost:8181/v1/data/document/upload/allow

# default allow := false

allow if {
	resources := input.resources

	input.path == ["api", "document", "upload"]
	input.method == "POST"

	user_id := resources.user.id
	document_author_id := resources.document.authorId

	# Auth user shoud be the document author
	user_id == document_author_id

	# Auth user should be an employee
	resources.user.roles[_] == "employee"
}
