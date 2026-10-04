# 03 Auth and security

## What this section delivers

People can sign in, what they can do depends on their role, every important action is written to an audit trail, and scans can only target ranges an administrator has authorized.

## Roles

Admin can do everything. Operator can request and view scans, see the authorized ranges and see assets, but cannot manage users, change authorized ranges or read the audit trail. Anything without an explicit rule requires a signed in user, so a forgotten endpoint is closed rather than open. Health endpoints are the deliberate exception.

## Sessions

An access token lasts 15 minutes and is a signed JWT. A refresh token lasts 7 days, is random, and only its hash is stored. Using a refresh token swaps it for a new one. If an already used refresh token shows up again, someone is replaying a copy, so every session for that user is ended and the event is audited.

Access tokens are stateless, but the account is checked on every request. That means disabling a user or changing their role takes effect on the next request instead of when the token expires. It costs one small query per request, which is the right trade for a tool like this.

Signing out revokes the refresh token. Changing or resetting a password revokes all of a user's sessions.

## Passwords and sign in

Passwords are hashed with PBKDF2 SHA256 at 600,000 iterations with a random salt per password. The cost is configurable and old hashes are upgraded the next time the user signs in. The policy asks for 12 to 128 characters and blocks blank, single repeated character and username containing passwords. Length matters more than composition rules.

Five wrong passwords lock an account for 15 minutes. A locked account, a disabled account, a wrong password and an unknown username all get the same 401 answer, and unknown usernames still burn the same hashing time, so neither the message nor the timing reveals which usernames exist. The real reason is in the audit trail. Guessing the current password through the change password endpoint counts towards the same lockout.

Sign in and refresh are also rate limited per client address, 10 a minute by default.

## Authorized ranges and scan control

Scanning is only allowed inside ranges an administrator has authorized, and they are global to the installation for now. Agent specific binding can be added in section 5 without changing this model.

Fixed rules apply whatever an administrator configures. Loopback, multicast, broadcast and reserved space can never be authorized or scanned, even partly. Only private ranges can be authorized unless public ranges are switched on in configuration. A scan target has to sit completely inside one authorized range, and cannot cover more than 65,536 addresses by default.

Range parsing is strict, so shorthand like 10.1, leading zeros, scope ids and host bits set are rejected instead of guessed at.

## Audit trail

Every sign in outcome, session event, user change, range change and scan request or denial is recorded with who, what, the target, the result, the caller address and the correlation id. Entries are written in the same save as the action itself, so an action and its record succeed or fail together. There is deliberately no foreign key to users, so the trail survives if a user is ever removed. Secrets such as passwords and tokens are never put in it, and a test checks that.

## First administrator

When there are no users and Bootstrap__AdminUsername and Bootstrap__AdminPassword are set, the first administrator is created at startup and a warning reminds you to remove the password from configuration. The password has to pass the same policy.

## Configuration

Jwt__SigningKey is required, at least 32 random bytes as base64. Generate one with openssl rand -base64 48. The app refuses to start without it. The development settings file carries a throwaway key for local use only, never reuse it anywhere real.

## Known limits

Access tokens carry a role claim but the account is the source of truth, so the role in the token is only a hint. There is no multi factor, SSO or secret vault yet, as agreed. The audit table is append only by convention, and making it enforce that in the database with permissions or a trigger belongs in the hardening section. Behind a reverse proxy the rate limiter needs forwarded headers configured so it sees the real client address, which also belongs in hardening.
