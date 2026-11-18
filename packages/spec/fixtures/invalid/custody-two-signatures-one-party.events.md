// why: A `custody_transferred` event with `held: false` whose sender and receiver roles are both signed by the same
// party. The two required-role signers of a two-party event are distinct parties whatever their keys
// (`signerBindingErrors`, REQ-EVENT-015, REQ-EVENT-003).
