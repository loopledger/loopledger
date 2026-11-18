// why: A `custody_transferred` event with `held: false` carries only the sender's signature. The schema requires two
// signatures from the named roles before a two-party event stops being held (REQ-EVENT-003, REQ-EVENT-004): a
// one-sided custody claim is valid only as held.
