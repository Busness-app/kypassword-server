`kysignon-user.json` is the exact HTTP body emitted by KySignOn's
`TestAccountSyncSCIMPayloadAndHeaders` (QueueAccountSyncEvent -> DispatchPendingEvents ->
deliver), run from an isolated archive of a2d5dbc59c0724fd96dc21a861f1e6ba33b38711.
Only the receiver in that test was instrumented to save the body. All identities are
synthetic. KyPassword signs this body with the same released syncauth.Sign implementation
and drives its actual mounted receiver; it does not rebuild the payload with its own encoder.
