
# TODOs for crypto work

## pick apart util.c/util.h into real files

the parts you've majorly changed need to be refactored into their own files. you can then drop them in as separate PRs making them easier to accept and understand.

## add password-update flow (this is new for the pam module)

use update_encrypted_password(...)

## write tests for crypto code

## verify "no password" scenarios for chauthtok

cases where old/new passwords are empty and NULL

does openssl key derivation fail? 

does encryption of blank fail?

remove any empty-password checks so the user can decide how and when to use empty passwords. we just need to gracefully handle them and fail if openssl cannot deal.

update in-code docs to talk about blank passwords once you know what you can support.

