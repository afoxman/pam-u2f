
# TODOs for crypto work

## figure out a PR strategy. isolate and test (as much as possible) to make the PRs separate and clean

look at the sum total of all changes. figure out how you want to stage the PRs. make a list in here, and include file/code references. 

- is the PR small enough to be accepted?
- is the code as isolated as possible?
- does it have tests?
- did you add tests for changes to existing code?

NOTE: logging has some #error tags to size of new code. existing debug_dbg -> log_xxxxx should stay as is. adds significant value.

### 1. Logging -- new code, add log_t* to cfg_t, debug_dbg -> log_xxxxx

-- split this into 2 PRs? 1 to introduce logging code and hook up debug_dbg, and another to transform debug_dbg->log_xxxxx
    I've seen them split up PRs that way before. they might prefer it.

* .gitignore
* cfg.c
* cfg.h
* debug.c
* debug.h
* defs.h
* log.c
* log.h
* util.c (most of it)
* util.h
* CMakeLists.txt (partial)
* Makefile.am (partial)
* pamu2fcfg/CMakeLists.txt (partial)
* pamu2fcfg/Makefile.am (partial)
* pamu2fcfg/pamu2fcfg.c (partial)
* tests/CMakeLists.txt
* tests/Makefile.am
* tests/cfg.c
* tests/test_log.c
* util.c (most of it)
* util.h (most of it)

TODO: more test cases needed? one per log type to both file and syslog, and cases for logging when log=NULL

### 2. Crypto -- encrypt and decrypt password (NOT change-password)

* b64.c
* b64.h
* crypt.c
* crypt.h
* fuzz/fuxx_format_parsers.c
* pam-u2f.c
* pamu2fcfg/CMakeLists.txt (partial)
* pamu2fcfg/Makefile.am (partial)
* pamu2fcfg/pamu2fcfg.c (partial)
* util.c (partial)
* util.h (partial)

TODO: test case updates for device_t struct -- python script and related code generates device_t-dependent code
TODO: test cases -- b64, crypto, fido interactions (if we have tests which already do this)

### 3. Crypto -- change password (pam_sm_chauthtok)

????


## crypt.c

- remove `format()` and replace with calls to `asprintf()`
- str_xxx functions are only used once or twice -- change out for string-modifying stuff like strtok. will need to strdup during the parent call, which is better than all this new code.
- throughout the file, tighten up the code to take up less space. shorten names, reduce line counts, tighten up prototypes, etc.

## pam-utf.c ln 443 -- update authfile with new encrypted password(s)

this code needs to update the user's last entry in the authfile, with all their device_t objects.

the code right now can generate a single authfile line (pamu2fcfg) and it can scan for a user's entry (ignores all the but the last one, pam-u2f).

i need to refactor this code, and expand it to include replacing the user's last row with an updated password. notes below.

```c
// scan the entire file
//   find the last line for this user ==> this is the one we're going to replace 
//   (note the file positions at the start (first char) and end (pos of \n + 1) of this line)
//
// create a new temp file next to the one we are renaming -- .tmpXXXXX
//   write(read(up-to-start-pos))
//
//   write the replacement line
//
//      user:devices[0]:devices[1]:...:devices[n]
//         device[i] (old_format)  = keyHandle,publicKey
//                   (!old_format) = keyHandle,publicKey,coseType,attributes,encryptedPassword
//
//   write(read(from-end-pos-to-EOF))
//   on error, delete .tmpXXXXX
//   on success, move .tmpXXXXX overtop of authfile (atomic replace)
```

## add password-update flow (this is new for the pam module)

use update_encrypted_password(...)

## verify "no password" scenarios for chauthtok

cases where old/new passwords are empty and NULL

does openssl key derivation fail? 

does encryption of blank fail?

remove any empty-password checks so the user can decide how and when to use empty passwords. we just need to gracefully handle them and fail if openssl cannot deal.

update in-code docs to talk about blank passwords once you know what you can support.

