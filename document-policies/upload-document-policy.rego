package document.upload
# import future.keywords.http

# https://localhost:8181/v1/data/document/upload/allow

default allow = false

allow if {

	input.path == ["api", "document", "upload"]
	input.method == "POST"

    resp := http.send({
        "method": "GET",
        "url": sprintf(
        "http://localhost:3000/api/policy-data/upload?userId=%s&authorId=%s",
        [input.userId, input.content.authorId]  # or input.body.authorId
        )
    })
    resources := resp.body

	user_id = resources.user.id
	document_author_id = resources.document.authorId

	# Auth user shoud be the document author
	user_id == document_author_id

	# Auth user should be an employee
	resources.user.roles[_] == "employee"
}
