package document.test

default allow = false

allow if {
  input.userId == "alice"
}