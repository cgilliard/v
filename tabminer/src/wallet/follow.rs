//! The wallet following the chain: where its outputs are, as blocks
//! make them.
//!
//! After every change of the chain's last block the wallet is told of
//! the outputs of the blocks it has not looked at ([`follow`]): which of
//! them are its own, and where each is.
//!
//! Where the chain has gone over to another branch, the wallet finds
//! where the branches part (the newest block it remembers looking at
//! that is still of the chain) and goes through the blocks of the new
//! branch from there: as many blocks as the branch is long, whatever
//! the chain holds. Nothing below is touched: outputs take their
//! positions in order, so what was made before the branches part is
//! where it was.
//!
//! Only where there are no blocks to go through (the wallet is further
//! behind than blocks' bodies are kept, or knows nothing of how far it
//! had looked) does it look through all the unspent outputs for its
//! own instead, by their memos.

use super::{Reconciled, Wallet, WalletError};
use crate::block::BodyRef;
use crate::chain::Chain;
use crate::hash::Digest;
use crate::hash::digest_to_bytes;
use crate::store::Backend;

/// What [`follow`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Followed {
    /// Blocks gone through, one by one.
    pub blocks: u32,
    /// Whether the unspent outputs were looked through instead.
    pub looked_through: bool,
    /// Outputs a restore's first scan found, and their total; the names
    /// it found; and whether there was such a scan.
    pub found: (usize, u128),
    pub names: usize,
    pub restored: bool,
    /// What holding the wallet against the chain changed: payments
    /// undone, outputs lost and found again.
    pub changed: Reconciled,
}

/// Brings `wallet` up to `chain`'s last block, at `now`: nothing is done
/// where it is there already, or while the chain has no state to read.
pub fn follow<B: Backend + 'static, V, W: Backend>(
    chain: &Chain<B, V>,
    wallet: &mut Wallet<W>,
    now: u64,
) -> Result<Followed, WalletError> {
    follow_when(chain, wallet, now, true)
}

/// [`follow`], told whether the chain here is the network's, or still
/// being caught up with (`whole`): a wallet made again from its words
/// looks for what it holds only in a chain that is all here. Looked for
/// in half a chain, what the rest of it holds would never be found.
pub fn follow_when<B: Backend + 'static, V, W: Backend>(
    chain: &Chain<B, V>,
    wallet: &mut Wallet<W>,
    now: u64,
    caught_up: bool,
) -> Result<Followed, WalletError> {
    let mut done = Followed::default();
    let Ok(state) = chain.whole() else { return Ok(done) };
    let snap = state.snapshot()?;
    let (height, tip) = snap.tip();
    let tip_bytes = digest_to_bytes(&tip);
    // From where outputs may have been undone: none, unless the chain
    // went back on blocks the wallet had looked at.
    let mut undone_from = None;
    if wallet.synced() != Some((height, tip_bytes)) {
        let on_chain = |h: u32, id: &[u8; 32]| {
            chain.header_at_of(&snap, h).ok().flatten().is_some_and(|header| digest_to_bytes(&header.hash()) == *id)
        };
        // The newest block looked at that is still of the chain: where
        // the wallet goes on from, and, if it is not the last it looked
        // at, where the branches part.
        let known = wallet.recent().find(|(h, id, _)| *h <= height && on_chain(*h, id)).copied();
        let from = match (known, wallet.synced()) {
            (Some((h, _, next)), synced) => {
                if synced.is_some_and(|(last, _)| last != h) {
                    undone_from = Some(next);
                }
                Some(h + 1)
            }
            // A wallet with nothing in it has nothing to find.
            (None, _) if wallet.outputs().is_empty() => Some(height + 1),
            (None, _) => None,
        };
        // The blocks from there up, each with where its outputs begin.
        // The newest block's are the last before the next position, and
        // each block's before those of the one after it (its commits of
        // names taking the positions after its outputs).
        let mut blocks: Vec<(u64, Vec<Digest>, u32, [u8; 32], u64)> = Vec::new();
        let mut whole = from.is_some() && on_chain(height, &tip_bytes);
        let mut end = snap.outputs().next;
        for h in (from.unwrap_or(height + 1)..=height).rev() {
            let body = chain.header_at_of(&snap, h).ok().flatten().and_then(|header| {
                let id = header.hash();
                Some((id, chain.body_of(&snap, &id).ok().flatten()?))
            });
            let Some((id, body)) = body else {
                whole = false;
                break;
            };
            let Ok(body) = BodyRef::from_bytes(&body) else {
                whole = false;
                break;
            };
            let made: Vec<Digest> = body.outputs().map(|o| o.commitment).collect();
            let Some(first) = end.checked_sub((made.len() + body.commits()) as u64) else {
                whole = false;
                break;
            };
            blocks.push((first, made, h, digest_to_bytes(&id), end));
            end = first;
        }
        if whole {
            for (first, made, h, id, end) in blocks.iter().rev() {
                wallet.locate(*first, made, *h, id, *end)?;
                done.blocks += 1;
            }
            // (Nothing to go through: it is here all the same.)
            if blocks.is_empty() {
                wallet.locate(0, &[], height, &tip_bytes, snap.outputs().next)?;
            }
        } else {
            wallet.relocate(&snap, now)?;
            wallet.locate(0, &[], height, &tip_bytes, snap.outputs().next)?;
            done.looked_through = true;
            // (Anything may have been undone.)
            undone_from = Some(0);
        }
    }
    // A wallet restored from its phrase finds what is its own, once.
    if wallet.scan_pending() && caught_up {
        done.found = wallet.scan(&snap, now)?;
        done.names = wallet.scan_names(&snap, now)?.0;
        wallet.clear_scan_pending()?;
        done.restored = true;
    }
    done.changed = wallet.reconcile(&snap, height, chain.keep() as u32, undone_from)?;
    // The payments made that a block now has: each one's path to that
    // block's state root, which is what proves it, taken while the
    // chain can still be taken back to that block.
    for (txid, at, position) in wallet.payments_to_prove() {
        if let Ok(past) = state.past(at)
            && let Ok(Some((record, path))) = past.prove(position)
        {
            wallet.prove_payment(&txid, at, position, &record.memo, path)?;
        }
    }
    // Its names, as the chain's records now have them.
    wallet.sync_names(&snap)?;
    // Rewards of blocks found, once no reorganization reaches them:
    // done with if the block is the chain's, forgotten if it is not.
    let settled = chain.keep() as u32;
    for (c, h, block) in wallet.rewards() {
        if block != [0; 32] && height >= h.saturating_add(settled) {
            let on_chain =
                chain.header_at_of(&snap, h).ok().flatten().is_some_and(|x| digest_to_bytes(&x.hash()) == block);
            match on_chain {
                true => wallet.reward_settled(&c)?,
                false => drop(wallet.forget(&c)?),
            }
        }
    }
    Ok(done)
}

/// What the wallet has, against the chain's state as it is: nothing
/// while there is no state to read.
pub fn balance<B: Backend + 'static, V, W: Backend>(
    chain: &Chain<B, V>,
    wallet: &Wallet<W>,
) -> Result<super::Balance, WalletError> {
    let Ok(state) = chain.whole() else { return Ok(super::Balance::default()) };
    let snap = state.snapshot()?;
    wallet.balance(&snap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockRef;
    use crate::chain::apply::tests::{extend_spending, extend_with, grow};
    use crate::chain::headers::tests::{easy, seed, table};
    use crate::chain::params::COIN;
    use crate::chain::verify::AcceptAllProofs;
    use crate::store::testing::MemBackend;

    const NOW: u64 = 1_800_000_000;

    fn chain() -> Chain<MemBackend, AcceptAllProofs> {
        let chain = Chain::open(MemBackend::new(), 64, easy(), seed(), AcceptAllProofs).unwrap();
        chain.set_dataset(table());
        chain
    }

    /// A wallet's outputs are confirmed when blocks make them, and it is
    /// told where they are whichever way it comes to know: block by
    /// block, or by looking through what is unspent.
    #[test]
    fn a_wallet_follows_the_chain() {
        let chain = chain();
        let mut wallet = Wallet::open(MemBackend::new()).unwrap().0;
        // A new wallet has nothing to find: it is where the chain is.
        grow(&chain, 3, 1);
        assert_eq!(follow(&chain, &mut wallet, NOW).unwrap(), Followed::default());
        assert_eq!(wallet.synced().map(|s| s.0), Some(3));
        // Blocks that pay it, and others between: gone through one by
        // one.
        let first = wallet.receive(1500 * COIN, NOW).unwrap();
        extend_with(&chain, &[first.block_output()]);
        grow(&chain, 2, 2);
        let second = wallet.receive(1500 * COIN, NOW).unwrap();
        extend_with(&chain, &[second.block_output()]);
        assert_eq!(balance(&chain, &wallet).unwrap().pending, 3000 * COIN as u128);
        assert_eq!(follow(&chain, &mut wallet, NOW).unwrap().blocks, 4);
        assert_eq!(balance(&chain, &wallet).unwrap().confirmed, 3000 * COIN as u128);
        assert_eq!(follow(&chain, &mut wallet, NOW).unwrap(), Followed::default());
        // A wallet that does not know how far it had looked looks
        // through what is unspent, and finds the same.
        let mut lost = Wallet::restore(MemBackend::new(), &wallet.phrase("").unwrap(), "", "").unwrap();
        let did = follow(&chain, &mut lost, NOW).unwrap();
        assert_eq!(did.found, (2, 3000 * COIN as u128));
        assert_eq!(balance(&chain, &lost).unwrap().confirmed, 3000 * COIN as u128);
        wallet.set_synced(None).unwrap();
        assert!(follow(&chain, &mut wallet, NOW).unwrap().looked_through);
        assert_eq!(balance(&chain, &wallet).unwrap().confirmed, 3000 * COIN as u128);
    }

    /// Gives `chain` these blocks, made on another.
    fn give(chain: &Chain<MemBackend, AcceptAllProofs>, blocks: &[Vec<u8>]) {
        for b in blocks {
            chain.apply_block(&BlockRef::from_bytes(b).unwrap(), crate::chain::headers::tests::NOW).unwrap();
        }
    }

    /// The chain goes over to another branch, and the wallets go with
    /// it. A payment in a block that is undone is unconfirmed again, to
    /// be sent again as it was signed; what the block made is lost, and
    /// found again where the other branch makes it; and a payment whose
    /// block is deep enough is done with.
    #[test]
    fn wallets_follow_the_chain_over_to_another_branch() {
        use crate::output::Output;
        use crate::wallet::{Balance, Reconciled};
        let (ours, theirs) = (chain(), chain());
        let mut alice = Wallet::open(MemBackend::new()).unwrap().0;
        let mut bob = Wallet::open(MemBackend::new()).unwrap().0;
        // (They spend what one block has: the branches here are short.)
        alice.set_min_confirmations(1);
        bob.set_min_confirmations(1);
        let both = |alice: &mut Wallet<MemBackend>, bob: &mut Wallet<MemBackend>| {
            (follow(&ours, alice, NOW).unwrap(), follow(&ours, bob, NOW).unwrap())
        };
        // A block both branches have pays alice; she pays bob, in a
        // block of ours alone.
        let reward = 1500 * COIN;
        let funded = extend_with(&ours, &[alice.receive(reward, NOW).unwrap().block_output()]);
        give(&theirs, std::slice::from_ref(&funded));
        both(&mut alice, &mut bob);
        let mut slate = {
            let state = ours.state();
            alice.send(100 * COIN, None, &state.snapshot().unwrap(), NOW).unwrap()
        };
        bob.receive_slate(&mut slate, NOW).unwrap();
        let signed = alice.finalize(&slate, NOW).unwrap();
        // (A block carrying it: what it spends, what it makes, and the
        // block's own reward with its fee.)
        let carrying = |chain: &Chain<MemBackend, AcceptAllProofs>, tx: &crate::transaction::Transaction, tag: u32| {
            let paid = Output::to_key_hash(&[tag as u8; 32], reward + tx.balance() as u64);
            let mut made: Vec<_> = tx.outputs.iter().map(|o| o.block_output()).collect();
            made.push(paid.block_output());
            extend_spending(chain, &tx.spent_positions(), &made)
        };
        carrying(&ours, &signed.tx, 1);
        both(&mut alice, &mut bob);
        let (a, b) = (balance(&ours, &alice).unwrap(), balance(&ours, &bob).unwrap());
        assert_eq!((a.locked, b.confirmed), (0, 100 * COIN as u128));
        assert!(a.confirmed > 0 && a.confirmed < 1400 * COIN as u128);
        // (Their lists say the same: sent and in a block, received.)
        use crate::wallet::list::{Kind, Stage};
        let rows = |w: &Wallet<MemBackend>| w.list().iter().map(|r| (r.kind, r.stage)).collect::<Vec<_>>();
        assert_eq!(rows(&alice), [(Kind::Sent, Stage::Confirmed)]);
        assert_eq!(rows(&bob), [(Kind::Received, Stage::Confirmed)]);

        // Their branch is longer, and has no such block: ours is undone.
        give(&ours, &grow(&theirs, 2, 7));
        let (did_a, did_b) = both(&mut alice, &mut bob);
        // Found by the blocks of the new branch alone, two of them:
        // the unspent outputs were not looked through.
        assert!(!did_a.looked_through && !did_b.looked_through);
        assert_eq!((did_a.blocks, did_b.blocks), (2, 2));
        assert_eq!(did_a.changed, Reconciled { undone: 1, lost: 1, ..Default::default() });
        assert_eq!(did_b.changed, Reconciled { lost: 1, ..Default::default() });
        let undone = balance(&ours, &alice).unwrap();
        assert_eq!((undone.confirmed, undone.locked, undone.lost), (0, reward as u128, a.confirmed));
        assert_eq!(balance(&ours, &bob).unwrap(), Balance { lost: 100 * COIN as u128, ..Default::default() });
        assert_eq!(rows(&alice), [(Kind::Sent, Stage::Pooled)]);
        assert_eq!(rows(&bob), [(Kind::Received, Stage::Orphaned)]);
        // The payment is there to be mined again, at where what it
        // spends is now.
        let again = {
            let state = ours.state();
            let unconfirmed = alice.unconfirmed(&state.snapshot().unwrap()).unwrap();
            assert_eq!(unconfirmed.len(), 1);
            alice.resend(&unconfirmed[0].txid).unwrap()
        };
        assert!(again.verify_signatures() && again.txid() == signed.tx.txid());

        // Their branch has it, further on: all is as it was, each
        // output where it now is.
        give(&ours, &[carrying(&theirs, &again, 2)]);
        let (did_a, did_b) = both(&mut alice, &mut bob);
        assert_eq!((did_a.changed.returned, did_b.changed.returned), (1, 1));
        assert_eq!((balance(&ours, &alice).unwrap(), balance(&ours, &bob).unwrap()), (a, b));
        assert_eq!(rows(&alice), [(Kind::Sent, Stage::Confirmed)]);
        assert_eq!(rows(&bob), [(Kind::Received, Stage::Confirmed)]);
        // And bob spends what he was paid, from where it is.
        let state = ours.state();
        let back = bob.send(50 * COIN, None, &state.snapshot().unwrap(), NOW).unwrap();
        assert_eq!(back.inputs.len(), 1);
        drop(state);
        // Deep enough, the payment is done with.
        assert_eq!(alice.sent().len(), 1);
        give(&ours, &grow(&theirs, 64, 9));
        assert_eq!(follow(&ours, &mut alice, NOW).unwrap().changed, Reconciled { settled: 1, ..Default::default() });
        assert!(alice.sent().is_empty());
        // (Done with, its row stays as it was.)
        assert_eq!(rows(&alice), [(Kind::Sent, Stage::Confirmed)]);
    }
}
