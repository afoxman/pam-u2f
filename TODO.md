
# TODOs for crypto work

## figure out a PR strategy. isolate and test (as much as possible) to make the PRs separate and clean

look at the sum total of all changes. figure out how you want to stage the PRs. make a list in here, and include file/code references. 

- is the PR small enough to be accepted?
- is the code as isolated as possible?
- does it have tests?
- did you add tests for changes to existing code?

NOTE: logging has some #error tags to size of new code. existing debug_dbg -> log_xxxxx should stay as is. adds significant value.

## add password-update flow (this is new for the pam module)

use update_encrypted_password(...)

## verify "no password" scenarios for chauthtok

cases where old/new passwords are empty and NULL

does openssl key derivation fail? 

does encryption of blank fail?

remove any empty-password checks so the user can decide how and when to use empty passwords. we just need to gracefully handle them and fail if openssl cannot deal.

update in-code docs to talk about blank passwords once you know what you can support.

