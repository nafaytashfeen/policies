package document.sign

# Test that an “employee” is allowed to sign
test_sign_allowed_when_employee if {
    allow
        with http.send as {"body": {"user": {"roles": ["employee"]}}}
        with input as {
          "path":   ["api", "document", "9f482556-f58b-4972-996d-305dc494447c", "sign"],
          "method": "POST",
          "userId": "05584243-a0ac-487d-afde-b2d2636c4e50",
          "documentId": "9f482556-f58b-4972-996d-305dc494447c"
        } 
}

test_sign_not_allowed_when_not_employee if {
    allow
        with http.send as {"body": {"user": {"roles": ["employee"]}}}
        with input as {
          "path":   ["api", "document", "9f482556-f58b-4972-996d-305dc494447c", "sign"],
          "method": "POST",
          "userId": "8319b8d8-5fff-435f-a6a0-8ecd5b3a2575",
          "documentId": "9f482556-f58b-4972-996d-305dc494447c"
        } 
}