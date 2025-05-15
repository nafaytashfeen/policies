package utils.role

get_user_roles(user_id, roles) := currentUserRoles if {
	some i
	roles[i].userId == user_id
	currentUserRoles := roles[i].roles
}
