# XMR lane: rule upgrades without stopping the pool

Status: designed, not implemented. Nothing in this document runs yet.

Design study of 2026-10-03, written for node operators and miners. Every
number below is a proposal until the operator rules on it, and is marked
"proposed" where it appears. Where this page and the code disagree, the code
is what runs today, and today is described in section 1. Payout scheme: Work
Receipt Settlement (WRS), pay-per-receipt.

## 1. The problem: today every rule change is a new pool

On the Monero lane every consensus parameter is part of the pool identity
(`lane-rules.md`). The digest of the rules sits inside the pool tag, the pool
tag is in every lane block's coinbase and in the handshake between nodes, and
the owed ledger's digest changes shape the moment one rule bit changes. That
was a deliberate choice: two nodes with different rules must never fork the
ledger silently.

The price is that any rule change, even adding one field, is a new pool by
construction. The practice so far has been a restart with a fresh
`--pool-genesis` (`lane-rules.md`, section 5). Nodes on the old rules see the
new blocks as another pool's blocks and keep mining alone; the balances owed
on the old ledger are not carried over by the protocol and have to be
re-seeded by hand, or they are stranded. For a stagenet lane that changes
every week this is tolerable. For a pool that is meant to run for years with
miners' money in its ledger it is not.

The goal of this design, in one line: new rules push old rules out, the pool
renews without stopping, there is no new genesis, and owed balances are
continuous across the change.

## 2. How a rule change activates without stopping

The design splits two things that are one thing today: the identity of the
pool and the rules it runs.

* **The pool identity is fixed for life.** It is the network, the chain id
  and the pool genesis, and nothing else. Rules are no longer part of it.
* **Rules come in epochs.** Epoch 1 is the rule set the pool starts with.
  Every later rule set is a new epoch: a number, the digest of its rules and
  the Monero height from which it applies. A new binary ships the proposal
  for an epoch as data (a deployment descriptor: epoch number, rules digest,
  activation kind, start height, timeout height), not as a code path that
  flips by itself.
* **Every lane block says which epoch built it.** The pool's field in the
  coinbase carries the pool id, the epoch the block was built under and the
  highest epoch the builder's software knows. The field sits at a fixed place
  so that software of any age finds it in any later block.
* **Activation is computed from finalized work, not from the clock or from a
  file.** The tally of section 3 runs over lane blocks that are final (60
  Monero blocks deep, the lane's existing finality depth), in the order every
  node already books them. When the tally holds, the epoch locks in at that
  height; it activates a fixed number of heights later (GRACE, proposed 1440
  heights, about two days on mainnet). GRACE is the warning time: every node,
  upgraded or not, knows the activation height in advance.
* **The activation is a ledger event.** At the activation height a RATCHET
  event is appended to the owed ledger, at the same position on every node.
  It changes the rules in force and nothing else: no balance moves, no row is
  created or dropped, the sum of all owed balances is the same immediately
  before and after. The ledger digest commits the epoch (number, rules
  digest, activation height) by name, so two nodes that disagree about which
  epoch is in force disagree loudly at the next digest, never silently on a
  rule bit.
* **A block is judged by the epoch in force at its height.** Every node
  already recomputes every lane coinbase at its booking point
  (`coinbase-recompute.md`); it would now recompute under the rules of the
  block's epoch. Template builders switch rules by tip height, not wall
  clock. Work receipts minted before the activation height stay in every
  node's window and are paid by the next block, whichever epoch builds it:
  the window is geometry, the payout split is the rule of the block.
* **Forward only.** There is no deactivation and no fallback. A deployment
  that has not locked in by its timeout (proposed about 60 days on mainnet)
  has failed; the pool continues on the current epoch and a retry needs a new
  epoch number. Undoing a rule is a new epoch with the old values. This is
  the ledger's own rule (nothing final is ever rewound) applied to the rules
  themselves.
* **Reorgs cannot move it.** Lock-in and activation are read from final
  blocks only, and GRACE is at least the finality depth, so a Monero reorg
  shorter than the finality depth cannot change the activation height. A
  deeper reorg is the lane's existing finality boundary
  (`finality-boundary.md`), epoch or no epoch.
* **A node that was down learns it from the chain.** The signalling, the
  lock-in and the first block of the new epoch are all on the Monero chain or
  in the node's own replayed ledger. A node that was off across the boundary
  recomputes the same activation when it books the chain in order; it needs
  no peer to tell it.

Two activation kinds are proposed, both fixed in the format: by vote
(section 3) for mainnet, and by a published fixed height for operator-run
test networks and as the emergency path. In both cases an old node holds
(section 4) rather than forking.

## 3. Who votes: miners, by their work

The operator's principle: the people doing the hashing decide the rules, not
the people hosting the nodes. Who earns, votes.

### 3.1 The ballot rides under the miner's proof of work

Every stratum job a node hands out already binds a few bytes of side data
under the share's proof of work: the payee, the author share and a reserved
16-bit word that must be zero today. Every relay node already verifies that
binding when it admits a receipt. The design uses the reserved word as the
ballot: the epoch number the work votes for (0 = abstain) and one bit that
says whether the miner chose it or the node did. Cost: zero bytes on chain,
zero bytes per receipt, and nothing new to verify.

Sub-share work (raindrops) is hashes on the same job below the share
target, so it carries the same ballot and votes through its payee's receipts.

### 3.2 The tally weighs ballots like it weighs payouts

Each lane block pays its window by weights that every node computes from the
same inputs (`payout-fairness.md`). The design sums those same weights by
ballot: the block's ballot box. The box is a pure function of what every node
already holds to book the block, so every node computes the same box, and a
replay from the node's own store reproduces it. The weights are the payout
weights before reward and drain enter, decayed as pay is decayed, so recent
work counts more than old work in exactly the way it is paid.

The donation slice of each receipt is counted as abstain: the project does
not vote with miners' fees.

### 3.3 The default is delegation to the node, stated and revocable

A stock miner (xmrig with `-u ADDRESS.worker -p x`, no vote word) lends its
work to the ballot its node is configured with (`--vote <n>` on the node).
That work is flagged "delegated" in the ballot under the proof of work, so
the tally reports how much of the yes came from miners directly and how much
by delegation. A node whose operator has not set `--vote`, or has set
`--vote 0`, abstains, and so does the work delegated to it: an operator who
has not decided does not spend other people's work.

The delegated ballot is a per-session contract: a node that changes its
`--vote` binds new logins only; to apply the change to live sessions it must
withdraw the job, which every miner sees as a reconnect and a new login reply.

### 3.4 How to override with stock xmrig

Put one word in the stratum password field, which the lane does not otherwise
read:

```
xmrig -o NODE:PORT -u ADDRESS.worker -p vote=2      # my work votes for epoch 2
xmrig -o NODE:PORT -u ADDRESS.worker -p vote=0      # my work abstains, whatever the node says
```

or in `config.json`: `"pass": "vote=2"`. Several words may be joined with `;`
or `,`; unknown words are ignored, so passwords other pools use still work.
No xmrig change is needed. Work with a stated vote is flagged "own" under the
proof of work and the node's `--vote` does not apply to it.

### 3.5 How to check what your work votes

Three ways, cheapest first:

1. **The login reply.** The lane's stratum login reply carries a `c2pool`
   member with the fee terms. The design adds `vote` to it: the ballot bound
   to this session, its source (`own` or `delegated`), the node's own
   `--vote`, and the open deployments with their current yes share split
   into direct and delegated work. A stock miner learns what it is lending
   its work to before it hashes.
2. **Every job.** Each job push carries the ballot, the payee id and the job
   binding hash. With `proof=1` in the password the node also sends the
   coinbase opening for the job, so a proxy can recompute the binding and
   check that the blob it is about to hash commits exactly the stated ballot
   and payee. A node that echoes one ballot and binds another is caught on
   the first job.
3. **Any other node.** Receipts are relayed in the clear with their identity,
   ballot and flag. Any other node's dashboard lists the receipts it relayed,
   so a miner can see how its work was counted without its own node's help.

The node writes the job, so it can bind a ballot the miner did not choose.
The protocol cannot forbid that (no other node can tell a substituted ballot
from a miner's real choice), but it makes the lie cheap to catch and the exit
cheap to take: switch node, and the vote follows the payout identity. This is
the same trust boundary the payee and the node owner fee already sit on
(`review-criticals.md`, item 09).

### 3.6 When an epoch locks in (all numbers proposed)

On every finalized lane block, in chain order, a deployment passes if:

* yes is at least 75 percent of the voting work in the window (own and
  delegated ballots alike; abstainers excluded), and
* yes is at least 50 percent of all work in the window, abstainers included.

It locks in when it has passed on every finalized block for at least 48 lane
blocks (about a day at one lane block per 17 Monero blocks) and across at
least two full windows of work. The second condition keeps a small pool from
locking in on a few blocks; the first keeps a large pool from locking in on
a few minutes. Then GRACE, then activation.

Who can block: 25 percent of the work that takes a side, or any coalition of
abstain and no above 50 percent of all work. The direct/delegated split is
shown everywhere but is not a rule input: a delegated ballot counts like an
own one, and a minimum of direct votes would bring back the stall that
delegation removes. A node may show a warning when a lock-in is carried
mostly by delegation.

Ballots for an epoch that no published software implements are shown but
never lock in: a majority cannot stop the pool by voting for nothing.

### 3.7 Who holds what

* Developers propose: they write the epoch's code and publish its deployment
  descriptor. Without a descriptor a ballot is a number on a dashboard.
* Miners activate, by the rule above.
* Operators build jobs and follow. A node with the code switches at the
  activation height; a node without it holds (section 4). An operator's
  weight is its fee share plus the work of miners who said nothing, stated
  at login, flagged in every box, and taken back by any miner with one word.

Can operators stop a rule the miners want? Only by not upgrading, in which
case their nodes hold and their miners move. Can miners force a rule no
operator runs? Formally yes: if no node has the code, every node holds at
the activation height until someone ships it; that is the price of "miners
decide", bounded by the rule that undefined epochs never lock in. Can
developers push a rule? No: a descriptor nobody votes for fails at its
timeout.

Stated limits: a majority of work can pass anything if the rest abstains,
and work-weighted governance cannot bind a work majority; the minority's
protection is section 5, not the tally. A payee that earns only through
raindrops, with no receipt of its own in the window, earns and does not vote
(raindrops are off on mainnet today). Every node can see how much work was
delegated, not which node it was delegated to.

## 4. What an old node does: hold, never fork

An old node is one whose software does not know the epoch that is activating.
It can still read the pool id and the epoch fields in every block of its
pool, and it can still run the tally (it learns the deployment descriptor
from its peers in the handshake). So:

* **Before activation.** When half the window signals an epoch it does not
  know, it warns. At lock-in it prints the activation height and the advice
  to upgrade before it.
* **At activation.** It holds: it stops building templates, withdraws the
  stratum job and parks logins. Its ledger cursor stops just before the
  activation height, so nothing is ever booked under the wrong rules. It
  keeps its chain view, its peer links, its ingestion and storage of receipts
  and block frames, and its dashboard. It shows one alarm (`rules-behind`)
  with the epoch, the activation height and the number of its pool's blocks
  it has seen but not booked, and a reminder now and then. This is not a
  rejection and is not counted as one.
* **It is never banned and never a stranger.** Upgraded nodes accept it as a
  follower; it accepts them. Nobody is disconnected for its version. A block
  of its own pool is never treated as another pool's block, whatever epoch
  built it. Its ledger is a frozen prefix of the upgraded nodes' ledger,
  never a different ledger.

### 4.1 Miners on an old node are idle, not robbed

The receipts they earned up to the activation height sit in every node's
window and are paid by the next block, under whatever epoch it is built.
Their owed balances are shared ledger state and are drained in every block
the majority finds, oldest first, exactly as before. Their payout addresses
are already known to the ledger from earlier blocks. After the activation
height their node hands out no jobs, so their rigs fail over to another node
or wait for the upgrade. They lose nothing they earned and earn nothing new
on that node until it is upgraded. This is better than the V36 behaviour,
where a node left behind kept paying its miners on a chain the pool no longer
built on.

### 4.2 Catch-up: upgrade and restart, no re-sync

The operator installs the new binary and restarts. The store opens, the
ledger replays to the frozen state, and the node resumes booking the chain in
order. At the activation height its tally yields the same lock-in as
everyone else's, it appends the same RATCHET event at the same position, and
it books every block it saw while holding from the frames it stored then.
Catch-up time is bounded by local replay, not by other nodes' repair
horizons; no state is copied from another node. The design asks a holding
node to keep those frames for the deployment timeout (about 60 days). A node
that was fully down across the boundary catches up through the existing relay
repair within its horizon; beyond it, the verified resync of
`finality-boundary.md` (also design) is the path.

Fail-closed: an old binary started on a store that already holds a RATCHET
event for an epoch it does not know refuses to open with a clear message
("store written under epoch 2, this build knows epoch 1, upgrade"). It never
replays the ledger silently under the old rules.

## 5. What a vote can never change

Some things must be the same forever, either because an old node must be able
to read them in every future block, or because they protect money already
earned. Changing one of them is a true flag day (a new genesis). The design
calls this list the constitution. Proposed contents:

1. The pool id, the on-chain field that carries it with the epoch numbers,
   and its fixed place in the coinbase.
2. The activation rule itself: the tally, its thresholds and windows, GRACE,
   the timeout, forward only, no deactivation, both activation kinds, and
   the layout of a deployment descriptor.
3. The RATCHET ledger event, its payload and its position.
4. The framing of the owed ledger digest: an existing tag never changes its
   meaning or width; a new rule gets a new tag.
5. The finality depth (60 Monero blocks) and the booking order. The
   activation stands on them, so they cannot be moved by an activation.
6. The ballot field and the tally's reading of it.
7. The handshake fields and the follower rules: nobody is banned for its
   version.
8. The store rule: data written by newer software than the reader is refused,
   never reinterpreted.
9. For now, the roundabout geometry (window length, half-life, share
   difficulty, binding mode). Changing it needs a rebuild protocol that does
   not exist yet, so until then it is constitutional. This is an honest
   limit, not a principle.
10. **Minority protection (R-MIN).** The RATCHET event never lowers a
    balance; that is an invariant of the model, not a promise. But a rule
    could still starve a balance after the boundary without "lowering" it:
    pay it arbitrarily slowly, decay it as dust faster, park it behind a
    minimum, redirect the residual, or seed new liabilities ahead of it. So
    the design makes those rules constitutional on mainnet or grandfathers
    them: no minimum balance for payment, no seeded balances, the residual
    sink fixed, a floor on how fast old balances must drain (an epoch may pay
    them faster, never slower), and dust decay applied by the schedule in
    force when a balance went dormant. With these, "a majority cannot
    reduce, delay or redirect a balance already earned" is an invariant of
    the model (to be checked in TLA+ at small bounds, like the lane's other
    invariants), not a hope.

Everything else is up to the vote: fee version, the raindrop rule bits, the
coinbase fields between the fixed ones, the drain parameters above their
floor, output caps, tie rules, relay frame versions. Those change future
credit, and future credit is the majority's to decide: it is their work.

## 6. Numbers (all proposed, none ruled)

| Quantity | mainnet | stagenet / testnet | regtest |
|---|---|---|---|
| Yes needed, of voting work | 75 percent | 75 percent | 75 percent |
| Yes needed, of all window work | 50 percent | 50 percent | 50 percent |
| Lock-in must hold for (lane blocks) | 48 (about a day) | 8 | 2 |
| Lock-in must hold across (work) | 2 full windows | 1 window | none |
| GRACE (Monero heights from lock-in to activation) | 1440 (about 2 days) | 120 | 2 x finality depth |
| Timeout (heights after the deployment starts) | 43 200 (about 60 days) | 10 080 | 1000 |
| Finality depth (existing, constitutional) | 60 | 60 | as configured |

Why 75 and not 95: the question is not noise (the box is a census of the
window, not a sample) but who can say no. A quarter of the work that takes a
side is the proposed size of a minority that can block a rule. Bitcoin's
version bits let 5 percent of blocks block; classical p2pool and the lane's
V36 predecessor let 5 percent of shares block; this design lets 25 percent of
voting work block, and any abstain-plus-no coalition above half of all work.

## 7. Compared with how others upgrade

Bitcoin's BIP9 version bits are signalled by whoever builds the block
template, which in practice is the pool operator; a stratum v1 miner cannot
set the bits and can only find out what its pool signalled by watching the
chain. Classical p2pool switches to a new share version when 95 percent of
recent shares signal it, and the signal is the node software's version, so
miners on a node had no say, and nodes that did not upgrade could not read
the new shares and forked off. Monero P2Pool upgrades its sidechain at a
published date and time; every node must update before it to keep mining.
Here the ballot is each miner's own work, under its own proof of work: by
default delegated to the node operator's stated choice and labelled as such,
revocable by any miner with one word in the password, counted with the same
weights that pay, and old nodes hold instead of forking off. The economics
are the same as Bitcoin's: a large operator still carries the weight of
miners who say nothing. The difference is that this weight is labelled, and
the miners can take it back without moving.

## 8. What this document is not

It is a design, not a specification of running code. The format changes it
needs (the pool id field, the ballot in the side data, the RATCHET event and
the epoch section in the ledger digest, the store schema, the handshake
epoch list) each move digests that every node must agree on, so the intent
is to ship them together, once, before the mainnet genesis: the last flag
day. The vote itself, the login reply and the per-job proof can follow as
ordinary upgrades once the format exists. Open points for the operator: the
thresholds and windows of section 6, whether a direct-vote warning line is
wanted, and the exact list of constitutional items in section 5.
