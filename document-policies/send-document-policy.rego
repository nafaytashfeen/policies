package document.send

# import future.keywords.http

import data.utils.role.get_user_roles

# https://localhost:8181/v1/data/document/send/allow

default allow = false

# Should be signed at least by a manager that is not the author
some_signature_by_manager(signatures, roles, authorId) if {
	some s
	currentSignature = signatures[s]
	currentUserId = currentSignature.authorId
	currentUserId != authorId

	currentUserRoles = get_user_roles(currentUserId, roles)
	currentUserRoles[_] == "manager"
}

# Should be signed at least by the author
some_signature_by_author(signatures, authorId) if {
	some s
	currentSignature = signatures[s]
	authorId == currentSignature.authorId
}

# Should be signed by the sender
some_signature_by_sender(signatures, userId) if {
	some s
	currentSignature = signatures[s]
	userId == currentSignature.authorId
}

allow if {   
    # Fetch the policy‐data from the Express endpoint
    resp := http.send({
        "method": "GET",
        "url": sprintf(
          "http://localhost:3000/api/policy-data/documents/%s?userId=%s&receiverId=%s",
          [input.resources.document.id, input.resources.userId, input.resources.receiverId]
        )
    })
    resources := resp.body

	input.path == ["api", "document", resources.document.id, "send"]
	input.method == "POST"

	userId := resources.userId
    authorId := resources.document.authorId
    receiverId := resources.receiverId
    roles := resources.roles
    signatures := resources.document.signatures

	# Receiver shoud match document receiver
	receiverId == resources.document.receiverId

	## Roles ##
	# Auth user should be an employee
	userRoles = get_user_roles(userId, roles)
	userRoles[_] == "employee"

	# Receiver user should be a client
	receiverRoles = get_user_roles(receiverId, roles)
	receiverRoles[_] == "client"

	# Should be signed at least by a manager that is not the author
	some_signature_by_manager(signatures, roles, authorId)

	# Should be signed at least by the author
	some_signature_by_author(signatures, authorId)

	# Should be signed by the sender
	some_signature_by_sender(signatures, userId)
}
