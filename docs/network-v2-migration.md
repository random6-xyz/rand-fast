# Migrating network reports to rand-fast/v2

The `net` and `diagnose` JSON reports now use `"schema":"rand-fast/v2"`.
Other commands, including daemon reports, continue to use `rand-fast/v1`.
Consumers should select a parser using both `schema` and `command`; consumers
that accept only v1 must be updated before reading these two reports.

In `net`, each endpoint's `retrans_ratio` is now `null`. In `diagnose`,
`data.measured.retrans_ratio` is also `null`, and
`data.measured.retransmissions` contains the observed retransmission count.
The existing `net` total and endpoint `retransmissions` counts remain
available. Treat `null` as unavailable, not as zero. The previous v1 numeric
ratio was invalid: TCP receive probe events are not a count of transmitted
segments and cannot supply the denominator for a transmission retransmission
rate. A v1 ratio should not be interpreted as a packet loss rate.

The text reports retain retransmission counts and state that the rate is
unavailable because transmitted segment counts are not collected. The
`net` endpoint table no longer includes a ratio column.

`diagnose` no longer uses retransmissions or their former ratio to score
Network. It can still rank Network using sufficiently sampled off-CPU socket
waits. Retransmissions alone do not establish a network ranking; if no cause
has sufficient scorable evidence, the text report says so instead of claiming
that nothing was measured. Rankings and their confidence shares may therefore
change even for otherwise identical measurements.
