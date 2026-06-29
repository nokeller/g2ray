### [449] Private project files on S3 keyed by TIMESTAMP path: files saved at `/uploads/<unix_timestamp>/1.py`; the only "id" is the upload timestamp (date-hour-min-sec) → script all timestamps for a day and fuzz → download other users' private project files — Arbaz Hussain [NEW ★ time-based path = tiny keyspace; fuzz the time window to reach "private" files]
- Where: S3 `/uploads/<timestamp>/<file>` (private and public use the same predictable scheme).
- Approach/how-found: both public and private projects stored files under a unix-timestamp directory; since a timestamp only spans a day's worth of seconds, he generated all timestamps for 24h and fuzzed → accessed others' private files (fix: an auth-token verifier on S3 fetch).
- Test: when files are addressed by timestamp (or any low-entropy value: counter, date, short hash), enumerate the whole window; "private" storage with a predictable path is open.
- Q: "Are uploaded files addressed by a timestamp/sequential/short value I can enumerate? Is there any auth on the storage URL, or just the path?"

### [450] Facebook private events — invite/RSVP arbitrary users (privacy/privesc, $2,000): the invite request's `profilechooseritems` is a user id; fuzz it to invite people NOT in your friend list (against policy) and even post "X is going to this event" on their behalf — Armaan Pathan [NEW: forced association — add/RSVP arbitrary users to your object by id]
- Where: event invite request, `profilechooseritems` (user id).
- Approach/how-found: inviting himself exposed his user id in `profilechooseritems`; swapping it to non-friends (incl. a brand-new account with no mutual friends) invited them to his private event and let him post their attendance — bypassing the friends-only policy.
- Test: invite/add-guest/RSVP actions keyed on a user id → set arbitrary ids to force-associate users with your object and post on their behalf (reputation/spam impact).
- Q: "Can I invite/RSVP/add arbitrary user ids to my event/group, ignoring the friends-only rule? Can I post attendance/actions on their behalf?"
