//! Tests of the wallet, against a chain that is a list of outputs.

use super::*;
use crate::store::testing::{Lost, MemBackend};

const NOW: u64 = 1_800_000_000;
const COIN: u64 = crate::chain::params::COIN;

/// The chain's outputs: each one's commitment, memo and amount, and
/// whether it is unspent, at the position of its place in the list.
#[derive(Default)]
struct Outputs(Vec<(Commitment, Memo, u64, bool)>, u32);

impl Unspent for Outputs {
    fn holds(&self, position: u64, commitment: &Commitment) -> io::Result<bool> {
        Ok(self.0.get(position as usize).is_some_and(|(c, _, _, live)| *live && c == commitment))
    }

    /// (Every output is of the first block, and the chain is as long
    /// as the second number says: one block, if it says nothing.)
    fn confirmations(&self, position: u64, commitment: &Commitment) -> io::Result<Option<u32>> {
        Ok(self.holds(position, commitment)?.then_some(self.1.max(1)))
    }

    fn each(&self, f: &mut dyn FnMut(u64, &Commitment, &Memo, u64)) -> io::Result<()> {
        for (position, (c, memo, amount, live)) in self.0.iter().enumerate() {
            if *live {
                f(position as u64, c, memo, *amount);
            }
        }
        Ok(())
    }
}

impl Outputs {
    /// A block makes `outputs`: they are there from now on, and the
    /// wallets are told where.
    fn make(&mut self, outputs: &[Output], wallets: &mut [&mut Wallet<MemBackend>]) {
        let first = self.0.len() as u64;
        self.0.extend(outputs.iter().map(|o| (o.commitment, o.memo, o.amount, true)));
        let made: Vec<Commitment> = outputs.iter().map(|o| o.commitment).collect();
        for wallet in wallets {
            wallet.locate(first, &made, 1, &[0; 32], first + made.len() as u64).unwrap();
        }
    }

    /// A block takes `tx`: what it spends is spent, and what it makes is
    /// made.
    fn take(&mut self, tx: &Transaction, wallets: &mut [&mut Wallet<MemBackend>]) {
        for input in &tx.inputs {
            assert!(self.holds(input.position, &input.commitment()).unwrap(), "spends what is not there");
            self.0[input.position as usize].3 = false;
        }
        self.make(&tx.outputs, wallets);
    }
}

/// A wallet that spends what one block has, as these tests' chains are
/// of one block.
fn new() -> Wallet<MemBackend> {
    let mut wallet = Wallet::open(MemBackend::new()).unwrap().0;
    wallet.set_min_confirmations(1);
    wallet
}

/// A wallet with one confirmed output of `amount`.
fn funded(chain: &mut Outputs, amount: u64) -> Wallet<MemBackend> {
    let mut wallet = new();
    let out = wallet.receive(amount, NOW).unwrap();
    chain.make(&[out], &mut [&mut wallet]);
    wallet
}

/// The wallet as it is found when its file is opened again.
fn reopened(wallet: &Wallet<MemBackend>, password: &str) -> Result<Wallet<MemBackend>> {
    let image = wallet.records.backend().image(Lost::None);
    let (mut wallet, _) = Wallet::open_with(MemBackend::from_image(image), &mut |_| Ok(password.to_string()))?;
    wallet.set_min_confirmations(1);
    Ok(wallet)
}

/// A wallet is made with a phrase, which is all it is made of: the same
/// phrase is the same keys. Its secret is locked under a password if
/// one is given, and opened only with it.
#[test]
fn a_wallet_is_its_phrase() {
    let (wallet, phrase) = Wallet::open_with(MemBackend::new(), &mut |ask| {
        assert_eq!(ask, Ask::New);
        Ok("correct horse".into())
    })
    .unwrap();
    let phrase = phrase.expect("a new wallet says its phrase");
    assert_eq!(phrase.split(' ').count(), 12);
    assert!(wallet.locked());
    assert_eq!(wallet.phrase("correct horse").unwrap(), phrase);
    assert!(matches!(wallet.phrase("wrong"), Err(WalletError::WrongPassword)));
    // Opened again: asked to unlock, and with nothing new to say.
    assert!(matches!(reopened(&wallet, "wrong"), Err(WalletError::WrongPassword)));
    let image = wallet.records.backend().image(Lost::None);
    let (again, said) = Wallet::open_with(MemBackend::from_image(image), &mut |ask| {
        assert_eq!(ask, Ask::Unlock);
        Ok("correct horse".into())
    })
    .unwrap();
    assert!(said.is_none() && again.master == wallet.master);
    // Restored from the phrase elsewhere: the same keys and memos.
    let nonce = [7u8; NONCE];
    let restored = Wallet::restore(MemBackend::new(), &phrase, "", "").unwrap();
    assert!(restored.scan_pending() && !restored.locked());
    assert_eq!(restored.key(&nonce).public_key(), wallet.key(&nonce).public_key());
    assert_eq!(restored.memo(&nonce), wallet.memo(&nonce));
    // Another passphrase is another wallet; and a wallet is not restored
    // over one.
    let other = Wallet::restore(MemBackend::new(), &phrase, "another", "").unwrap();
    assert_ne!(other.key(&nonce).public_key(), wallet.key(&nonce).public_key());
    let image = wallet.records.backend().image(Lost::None);
    assert!(matches!(Wallet::restore(MemBackend::from_image(image), &phrase, "", ""), Err(WalletError::Exists)));
    assert!(matches!(
        Wallet::restore(MemBackend::new(), "abandon ability", "", ""),
        Err(WalletError::Phrase(bip39::PhraseError::WordCount(2)))
    ));
    // The password is changed, and taken away.
    let mut wallet = wallet;
    assert!(matches!(wallet.set_password("wrong", "new"), Err(WalletError::WrongPassword)));
    wallet.set_password("correct horse", "").unwrap();
    assert!(!wallet.locked() && reopened(&wallet, "").unwrap().phrase("").unwrap() == phrase);
}

/// A wallet's outputs follow from its words: restored from the same
/// phrase it opens the memos of the outputs it made, and makes the same
/// outputs of them, with the same keys. Nobody else's memo opens.
#[test]
fn a_wallet_s_outputs_follow_from_its_words() {
    let entropy: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let phrase = bip39::phrase(&entropy);
    assert_eq!(phrase, "arctic live gadget display excess mandate sniff autumn people disorder affair horn");
    let wallet = Wallet::restore(MemBackend::new(), &phrase, "", "").unwrap();
    let again = Wallet::restore(MemBackend::new(), &phrase, "", "").unwrap();
    for (amount, nonce) in [(50_000_000_000u64, [3u8; NONCE]), (7, core::array::from_fn(|i| 200 - i as u8))] {
        let out = wallet.output_of(&nonce, amount);
        assert_eq!(out, again.output_of(&nonce, amount));
        let memo: Memo = out.memo;
        assert_eq!(again.open_memo(&memo), Some(nonce));
        assert_eq!(nonce[..], memo[..NONCE]);
        // The commitment is of the key of that nonce.
        assert_eq!(out.commitment, key_commitment(&pubkey_hash(&wallet.key(&nonce).public_key()), amount));
        // And it is nobody else's: not with the tag one off, not another
        // wallet's.
        let mut other = memo;
        other[NONCE] ^= 1;
        assert_eq!(wallet.open_memo(&other), None);
        assert_eq!(new().open_memo(&memo), None);
    }
}

/// A payment: the sender's slate, the recipient's output added to it,
/// and the sender's signature; what each wallet then has.
#[test]
fn a_payment_is_agreed_by_slate() {
    let mut chain = Outputs::default();
    let mut alice = funded(&mut chain, 100 * COIN);
    let mut bob = new();
    assert_eq!(
        alice.balance(&chain).unwrap(),
        Balance { confirmed: 100 * COIN as u128, spendable: 100 * COIN as u128, ..Default::default() }
    );

    let slate = alice.send(30 * COIN, None, &chain, NOW).unwrap();
    let fee = Wallet::<MemBackend>::min_fee(1);
    assert_eq!((slate.stage, slate.amount, slate.fee, slate.inputs.len(), slate.change), (1, 30 * COIN, fee, 1, 1));
    // Its input is reserved, and its change expected.
    let b = alice.balance(&chain).unwrap();
    assert_eq!((b.confirmed, b.reserved, b.pending), (0, 100 * COIN as u128, (70 * COIN - fee) as u128));
    assert_eq!(alice.pending_slates(), [(slate.id, 30 * COIN)]);
    assert!(matches!(alice.send(COIN, None, &chain, NOW), Err(WalletError::Insufficient { .. })));

    // As text, to the recipient, and back.
    let text = slate.to_text();
    assert!(text.starts_with("-----BEGIN TAB SLATE-----\n") && Slate::text_ends(&text));
    let mut answered = Slate::from_text(&format!("a line before\n{text}and one after")).unwrap();
    assert_eq!(answered, slate);
    assert!(matches!(alice.finalize(&answered, NOW), Err(WalletError::BadSlate("not a stage-2 slate"))));
    bob.receive_slate(&mut answered, NOW).unwrap();
    assert!(matches!(bob.receive_slate(&mut answered, NOW), Err(WalletError::BadSlate(_))));
    assert_eq!((answered.stage, answered.outputs.len()), (2, 2));
    assert_eq!(bob.balance(&chain).unwrap().unverified, 30 * COIN as u128);

    // What the recipient may not have changed.
    let refused = |alice: &mut Wallet<MemBackend>, change: &dyn Fn(&mut Slate)| {
        let mut slate = answered.clone();
        change(&mut slate);
        assert!(matches!(alice.finalize(&slate, NOW), Err(WalletError::BadSlate(_))));
    };
    refused(&mut alice, &|s| s.fee -= 1);
    refused(&mut alice, &|s| s.amount += 1);
    refused(&mut alice, &|s| s.outputs[1].amount += 1);
    refused(&mut alice, &|s| s.outputs[0].memo[0] ^= 1);
    refused(&mut alice, &|s| s.outputs.swap(0, 1));
    refused(&mut alice, &|s| s.inputs[0].1 += 1);
    refused(&mut alice, &|s| s.outputs.push(s.outputs[1]));
    assert!(matches!(bob.finalize(&answered, NOW), Err(WalletError::Unknown)));

    // Signed: a transaction the chain would take.
    let signed = alice.finalize(&answered, NOW).unwrap();
    assert!(signed.tx.verify_signatures() && signed.last_signatures.is_empty());
    assert_eq!((signed.tx.balance(), signed.tx.spent_positions()), (fee as i128, vec![0]));
    assert!(alice.pending_slates().is_empty());
    assert!(matches!(alice.finalize(&answered, NOW), Err(WalletError::Unknown)));
    let sent = alice.sent();
    assert_eq!((sent.len(), sent[0].txid, sent[0].fee), (1, signed.tx.txid(), fee));
    assert_eq!(alice.balance(&chain).unwrap().locked, 100 * COIN as u128);

    // In a block: each has what it was to have, and the sender's record
    // of the payment is done with.
    chain.take(&signed.tx, &mut [&mut alice, &mut bob]);
    let (a, b) = (alice.balance(&chain).unwrap(), bob.balance(&chain).unwrap());
    assert_eq!(
        a,
        Balance { confirmed: (70 * COIN - fee) as u128, spendable: (70 * COIN - fee) as u128, ..Default::default() }
    );
    assert_eq!(b, Balance { confirmed: 30 * COIN as u128, spendable: 30 * COIN as u128, ..Default::default() });
    // (Once its block is deep enough to rely on.)
    assert_eq!((alice.reconcile(&chain, 10, 5, Some(0)).unwrap(), alice.sent().len()), (Reconciled::default(), 1));
    assert!(alice.unconfirmed(&chain).unwrap().is_empty());
    assert_eq!(alice.reconcile(&chain, 15, 5, Some(0)).unwrap(), Reconciled { settled: 1, ..Default::default() });
    assert!(alice.sent().is_empty());
    // And all of it is there when the files are opened again.
    assert_eq!(reopened(&alice, "").unwrap().balance(&chain).unwrap(), a);
    assert_eq!(reopened(&bob, "").unwrap().balance(&chain).unwrap(), b);
}

/// A slate given up frees what it had reserved; and what cannot be paid
/// is refused before anything is.
#[test]
fn a_slate_is_given_up_and_what_cannot_be_paid_is_refused() {
    let mut chain = Outputs::default();
    let mut alice = funded(&mut chain, 100 * COIN);
    let before = alice.balance(&chain).unwrap();
    let slate = alice.send(30 * COIN, None, &chain, NOW).unwrap();
    assert!(matches!(alice.cancel_slate(&[9; 32]), Err(WalletError::Unknown)));
    alice.cancel_slate(&slate.id).unwrap();
    assert_eq!((alice.balance(&chain).unwrap(), alice.outputs().len()), (before, 1));
    assert!(alice.pending_slates().is_empty());

    assert!(matches!(alice.send(0, None, &chain, NOW), Err(WalletError::BadSlate(_))));
    assert!(matches!(alice.send(1, None, &chain, NOW), Err(WalletError::BadSlate(_))));
    assert!(matches!(alice.send(100 * COIN, None, &chain, NOW), Err(WalletError::Insufficient { .. })));
    assert!(matches!(alice.send(COIN, Some(1), &chain, NOW), Err(WalletError::FeeTooLow { .. })));
    assert!(matches!(alice.send(COIN, Fee::PerUnit(1), &chain, NOW), Err(WalletError::FeeTooLow { .. })));
    assert_eq!(alice.balance(&chain).unwrap(), before);
    // Change too small to be an output goes to the fee.
    let fee = Wallet::<MemBackend>::min_fee(1);
    let slate = alice.send(100 * COIN - fee - 5, None, &chain, NOW).unwrap();
    assert_eq!((slate.change, slate.fee, slate.outputs.len()), (0, fee + 5, 0));
    // Several outputs, where one is not enough.
    let mut chain = Outputs::default();
    let mut carol = new();
    let outs: Vec<Output> = (0..3).map(|_| carol.receive(10 * COIN, NOW).unwrap()).collect();
    chain.make(&outs, &mut [&mut carol]);
    let slate = carol.send(25 * COIN, None, &chain, NOW).unwrap();
    assert_eq!((slate.inputs.len(), slate.fee), (3, Wallet::<MemBackend>::min_fee(3)));
}

/// A wallet restored from its phrase finds its outputs by their memos,
/// and signs for them from the other half of each key's leaves; and an
/// output signs only as many times as its half has leaves.
#[test]
fn outputs_are_found_again_and_leaves_are_not_used_twice() {
    let mut chain = Outputs::default();
    let (mut first, phrase) = Wallet::open(MemBackend::new()).unwrap();
    let mine: Vec<Output> = (1..=3).map(|k| first.receive(k * COIN, NOW).unwrap()).collect();
    let mut stranger = new();
    let theirs = stranger.receive(50 * COIN, NOW).unwrap();
    chain.make(&[mine[0], theirs, mine[1], mine[2]], &mut [&mut first, &mut stranger]);
    chain.0[2].3 = false;

    let mut restored = Wallet::restore(MemBackend::new(), &phrase.unwrap(), "", "").unwrap();
    restored.set_min_confirmations(1);
    assert_eq!(restored.balance(&chain).unwrap(), Balance::default());
    // The two that are unspent, and nothing of anyone else's.
    assert_eq!(restored.scan(&chain, NOW).unwrap(), (2, 4 * COIN as u128));
    assert_eq!(restored.scan(&chain, NOW).unwrap(), (0, 0));
    restored.clear_scan_pending().unwrap();
    assert!(!reopened(&restored, "").unwrap().scan_pending());
    let mut found = restored.outputs();
    found.sort_by_key(|o| o.position);
    assert_eq!(
        found.iter().map(|o| (o.position, o.amount)).collect::<Vec<_>>(),
        [(Some(0), COIN), (Some(3), 3 * COIN)]
    );
    assert!(found.iter().all(|o| o.recovered && o.start < 8 && o.used == 0));
    // A wallet that lost where its outputs are finds that again.
    let mut lost = reopened(&first, "").unwrap();
    lost.t.outputs.values_mut().for_each(|o| o.position = None);
    lost.relocate(&chain, NOW).unwrap();
    assert_eq!(lost.balance(&chain).unwrap().confirmed, 4 * COIN as u128);

    // Leaves: the wallet that made the output signs from the first
    // eight in order; the restored one from the other eight.
    let c = mine[0].commitment;
    let mut t = first.t.clone();
    for k in 0..8u64 {
        let (key, last) = first.signing_key(&mut t, &c).unwrap();
        assert_eq!((key.next_index(), last), (k, k == 7));
    }
    assert!(matches!(first.signing_key(&mut t, &c), Err(WalletError::Exhausted)));
    let mut t = restored.t.clone();
    let start = u64::from(restored.owned(&c).unwrap().start);
    for k in 0..8u64 {
        let (key, _) = restored.signing_key(&mut t, &c).unwrap();
        assert_eq!(key.next_index(), 8 + (start + k) % 8);
    }
    assert!(matches!(restored.signing_key(&mut t, &c), Err(WalletError::Exhausted)));
    // A leaf is used on disk when the payment it signs is finalized.
    let mut bob = new();
    let mut slate = restored.send(COIN / 2, None, &chain, NOW).unwrap();
    bob.receive_slate(&mut slate, NOW).unwrap();
    let signed = restored.finalize(&slate, NOW).unwrap();
    assert!(signed.tx.verify_signatures());
    let spent = reopened(&restored, "").unwrap().outputs().into_iter().find(|o| o.state == State::Spent).unwrap();
    assert_eq!((spent.used, spent.amount), (1, 3 * COIN));
}

/// A reward is an output like another, and a record that it is one:
/// forgotten whole if its block comes to nothing.
#[test]
fn a_reward_is_recorded_and_forgotten() {
    let mut chain = Outputs::default();
    let mut miner = new();
    let kept = miner.reward(1500 * COIN, 7, NOW).unwrap();
    let dropped = miner.reward(1500 * COIN, 7, NOW).unwrap();
    assert_eq!(miner.rewards().len(), 2);
    miner.reward_found(&kept.commitment, &[5; 32]).unwrap();
    assert!(miner.forget(&dropped.commitment).unwrap() && !miner.forget(&dropped.commitment).unwrap());
    assert_eq!(miner.rewards(), [(kept.commitment, 7, [5; 32])]);
    chain.make(&[kept], &mut [&mut miner]);
    assert_eq!(miner.balance(&chain).unwrap().confirmed, 1500 * COIN as u128);
    miner.reward_settled(&kept.commitment).unwrap();
    let again = reopened(&miner, "").unwrap();
    assert!(again.rewards().is_empty() && again.outputs().len() == 1 && again.synced() == Some((1, [0; 32])));
}

/// A payment signed and not yet in a block is taken back, by another
/// spend of the same outputs that pays more; or sped up, the same
/// payment paying more. Each from the next leaf of every input.
#[test]
fn a_payment_sent_is_cancelled_or_sped_up() {
    let mut chain = Outputs::default();
    let mut alice = funded(&mut chain, 100 * COIN);
    let mut bob = new();
    let pay = |alice: &mut Wallet<MemBackend>, bob: &mut Wallet<MemBackend>, chain: &Outputs| {
        let mut slate = alice.send(30 * COIN, None, chain, NOW).unwrap();
        bob.receive_slate(&mut slate, NOW).unwrap();
        alice.finalize(&slate, NOW).unwrap()
    };
    let first = pay(&mut alice, &mut bob, &chain);
    let sent = alice.sent()[0].clone();
    let id = first.tx.txid();
    assert!(matches!(alice.cancel_sent(&[0; 32], None, &chain, NOW), Err(WalletError::Unknown)));

    // Sped up: the same output to the recipient, less change, more fee.
    let min = Wallet::<MemBackend>::min_bump_fee(&sent);
    assert!(matches!(alice.bump_sent(&id, Some(min - 1), &chain, NOW), Err(WalletError::FeeTooLow { .. })));
    let bumped = alice.bump_sent(&id, Some(min), &chain, NOW).unwrap();
    assert!(bumped.tx.verify_signatures() && bumped.tx.balance() == min as i128);
    assert_eq!(bumped.tx.spent_positions(), first.tx.spent_positions());
    assert_eq!(bumped.tx.outputs[1], first.tx.outputs[1]);
    assert_ne!(bumped.tx.outputs[0], first.tx.outputs[0]);
    // From the next leaf: no leaf signs twice.
    assert_eq!((first.tx.inputs[0].signature.index, bumped.tx.inputs[0].signature.index), (0, 1));
    assert!(matches!(alice.bump_sent(&id, None, &chain, NOW), Err(WalletError::Unknown)));
    assert_eq!(alice.sent().iter().map(|s| s.txid).collect::<Vec<_>>(), [bumped.tx.txid()]);
    assert_eq!(alice.resend(&bumped.tx.txid()).unwrap(), bumped.tx);

    // Taken back: all of it to this wallet, but a fee that is more again.
    let sent = alice.sent()[0].clone();
    let min = Wallet::<MemBackend>::min_replacement_fee(&sent);
    assert!(matches!(alice.cancel_sent(&sent.txid, Some(min - 1), &chain, NOW), Err(WalletError::FeeTooLow { .. })));
    let back = alice.cancel_sent(&sent.txid, None, &chain, NOW).unwrap();
    assert!(back.tx.verify_signatures() && back.tx.inputs[0].signature.index == 2);
    assert_eq!(
        (back.tx.outputs.len(), back.tx.outputs[0].amount, back.tx.balance()),
        (1, 100 * COIN - min, min as i128)
    );
    // In a block: the wallet has it all but the fee, once what was
    // never made is forgotten; and the recipient has nothing.
    chain.take(&back.tx, &mut [&mut alice, &mut bob]);
    alice.reconcile(&chain, 1, 0, Some(0)).unwrap();
    assert_eq!(alice.reconcile(&chain, 1, 0, Some(0)).unwrap().settled, 1);
    assert!(alice.balance(&chain).unwrap().pending > 0);
    assert_eq!(alice.prune_pending(&chain, &[]).unwrap(), 2);
    assert_eq!(
        alice.balance(&chain).unwrap(),
        Balance { confirmed: (100 * COIN - min) as u128, spendable: (100 * COIN - min) as u128, ..Default::default() }
    );
    assert_eq!(bob.prune_pending(&chain, &[]).unwrap(), 1);
    assert_eq!(bob.balance(&chain).unwrap(), Balance::default());
    // What is in a block is not taken back.
    let paid = pay(&mut alice, &mut bob, &chain);
    chain.take(&paid.tx, &mut [&mut alice, &mut bob]);
    assert!(matches!(alice.cancel_sent(&paid.tx.txid(), None, &chain, NOW), Err(WalletError::Landed)));
    assert!(matches!(alice.bump_sent(&paid.tx.txid(), None, &chain, NOW), Err(WalletError::Landed)));
    // What is kept is not forgotten: a pooled payment's outputs.
    let third = pay(&mut alice, &mut bob, &chain);
    let keep: Vec<Commitment> = third.tx.outputs.iter().map(|o| o.commitment).collect();
    assert_eq!((alice.prune_pending(&chain, &keep).unwrap(), bob.prune_pending(&chain, &keep).unwrap()), (0, 0));
}

/// The chain goes back on a block, and the wallet with it: a payment
/// that block had is one to be mined again, with its record to send it
/// from; an output it made is lost, kept apart from what is coming, and
/// found again or, in time, forgotten.
#[test]
fn what_a_block_undone_took_with_it_is_put_right() {
    let mut chain = Outputs::default();
    let mut alice = funded(&mut chain, 100 * COIN);
    let mut bob = new();
    let mut slate = alice.send(30 * COIN, None, &chain, NOW).unwrap();
    bob.receive_slate(&mut slate, NOW).unwrap();
    let signed = alice.finalize(&slate, NOW).unwrap();
    let before = chain.0.clone();
    chain.take(&signed.tx, &mut [&mut alice, &mut bob]);
    assert_eq!(alice.reconcile(&chain, 5, 10, Some(0)).unwrap(), Reconciled::default());
    assert_eq!(bob.balance(&chain).unwrap().confirmed, 30 * COIN as u128);
    let (paid, kept) = (bob.balance(&chain).unwrap(), alice.balance(&chain).unwrap());

    // The block is undone: the payment is unconfirmed again, and what
    // it made is in no block.
    let after = std::mem::replace(&mut chain.0, before);
    assert_eq!(
        alice.reconcile(&chain, 5, 10, Some(0)).unwrap(),
        Reconciled { undone: 1, lost: 1, ..Default::default() }
    );
    assert_eq!(bob.reconcile(&chain, 5, 10, Some(0)).unwrap(), Reconciled { lost: 1, ..Default::default() });
    assert_eq!(alice.reconcile(&chain, 5, 10, Some(0)).unwrap(), Reconciled::default());
    let a = alice.balance(&chain).unwrap();
    assert_eq!((a.confirmed, a.locked, a.pending, a.lost), (0, 100 * COIN as u128, 0, kept.confirmed));
    assert_eq!(bob.balance(&chain).unwrap(), Balance { lost: 30 * COIN as u128, ..Default::default() });
    // What is lost is not spent from, and not pruned away.
    assert!(matches!(bob.send(COIN, None, &chain, NOW), Err(WalletError::Insufficient { .. })));
    assert_eq!((alice.prune_pending(&chain, &[]).unwrap(), bob.prune_pending(&chain, &[]).unwrap()), (0, 0));
    // The payment is there to be sent again, as it was signed.
    let again = alice.unconfirmed(&chain).unwrap();
    assert_eq!((again.len(), alice.resend(&again[0].txid).unwrap()), (1, signed.tx.clone()));

    // Mined again: everything is as it was.
    chain.0 = after;
    assert_eq!(alice.reconcile(&chain, 6, 10, Some(0)).unwrap(), Reconciled { returned: 1, ..Default::default() });
    assert_eq!(bob.reconcile(&chain, 6, 10, Some(0)).unwrap(), Reconciled { returned: 1, ..Default::default() });
    assert_eq!((bob.balance(&chain).unwrap(), alice.balance(&chain).unwrap()), (paid, kept));
    assert_eq!(alice.reconcile(&chain, 16, 10, Some(0)).unwrap(), Reconciled { settled: 1, ..Default::default() });

    // Undone and never mined again: forgotten, when it has been gone
    // long enough; and it is all there when the file is opened again.
    chain.0.truncate(1);
    chain.0[0].3 = false;
    assert_eq!(bob.reconcile(&chain, 20, 10, Some(0)).unwrap().lost, 1);
    assert!(bob.is_lost(&slate.outputs[1].commitment) && reopened(&bob, "").unwrap().balance(&chain).unwrap().lost > 0);
    assert_eq!(bob.reconcile(&chain, 29, 10, Some(0)).unwrap(), Reconciled::default());
    assert_eq!(bob.reconcile(&chain, 30, 10, Some(0)).unwrap(), Reconciled { forgotten: 1, ..Default::default() });
    assert!(bob.outputs().is_empty() && bob.balance(&chain).unwrap() == Balance::default());
}

/// The wallet spends what has been in the chain long enough, and not
/// before: what a block just made, a block may yet unmake.
#[test]
fn what_is_spent_has_been_in_the_chain_a_while() {
    let mut chain = Outputs::default();
    let mut wallet = Wallet::open(MemBackend::new()).unwrap().0;
    let out = wallet.receive(100 * COIN, NOW).unwrap();
    chain.make(&[out], &mut [&mut wallet]);
    // Six blocks, unless told otherwise: confirmed from the first, and
    // not to be spent until the sixth.
    for blocks in 1..=5 {
        chain.1 = blocks;
        let b = wallet.balance(&chain).unwrap();
        assert_eq!((b.confirmed, b.spendable), (100 * COIN as u128, 0), "{blocks}");
        assert!(matches!(wallet.send(COIN, None, &chain, NOW), Err(WalletError::Insufficient { have: 0, .. })));
    }
    chain.1 = MIN_CONFIRMATIONS;
    assert_eq!(wallet.balance(&chain).unwrap().spendable, 100 * COIN as u128);
    let slate = wallet.send(COIN, None, &chain, NOW).unwrap();
    wallet.cancel_slate(&slate.id).unwrap();
    // Told otherwise.
    chain.1 = 2;
    wallet.set_min_confirmations(3);
    assert!(wallet.send(COIN, None, &chain, NOW).is_err());
    wallet.set_min_confirmations(2);
    assert!(wallet.send(COIN, None, &chain, NOW).is_ok());
    wallet.set_min_confirmations(0);
    assert_eq!(wallet.min_confirmations, 1);
}

/// A leaf seen signed from elsewhere (a copy of the wallet, or its file
/// as it was before) is not signed from again, nor any before it.
#[test]
fn a_leaf_signed_elsewhere_is_passed_over() {
    let mut chain = Outputs::default();
    let mut wallet = funded(&mut chain, 100 * COIN);
    let c = wallet.outputs()[0].commitment;
    assert_eq!(wallet.observe_signatures(&[(c, 2), ([1; 32], 5), (c, 12)]).unwrap(), 1);
    assert_eq!(wallet.owned(&c).unwrap().used, 3);
    // What is behind what the wallet knows changes nothing.
    assert_eq!(wallet.observe_signatures(&[(c, 1)]).unwrap(), 0);
    let mut t = wallet.t.clone();
    assert_eq!(wallet.signing_key(&mut t, &c).unwrap().0.next_index(), 3);
    assert_eq!(reopened(&wallet, "").unwrap().owned(&c).unwrap().used, 3);
}

#[test]
fn base64_is_base64() {
    for (bytes, text) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")] {
        assert_eq!(base64_encode(bytes.as_bytes()), text);
        assert_eq!(base64_decode(text).unwrap(), bytes.as_bytes());
    }
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(base64_decode(&base64_encode(&all)).unwrap(), all);
    for bad in ["Zg=", "Z===", "Zg==Zm9v", "Zh==", "Zm9!", "=m9v"] {
        assert_eq!(base64_decode(bad), None, "{bad}");
    }
}

/// The chain's names: the records, and the commits not yet revealed
/// (each one's hash, its output's memo, and where and when it was made).
#[derive(Default)]
struct Names {
    records: std::collections::HashMap<Vec<u8>, crate::name::Record>,
    commits: Vec<(Digest, Memo, u64, u32)>,
}

type Digest = crate::hash::Digest;

impl names::Registry for Names {
    fn record(&self, name: &[u8]) -> io::Result<Option<crate::name::Record>> {
        Ok(self.records.get(name).copied())
    }

    fn commit(&self, commit: &Digest) -> io::Result<Option<(u64, u32)>> {
        Ok(self.commits.iter().find(|c| c.0 == *commit).map(|c| (c.2, c.3)))
    }

    fn each_record(&self, f: &mut dyn FnMut(&crate::name::Record)) -> io::Result<()> {
        self.records.values().for_each(f);
        Ok(())
    }

    fn each_commit(&self, f: &mut dyn FnMut(&Digest, &Memo)) -> io::Result<()> {
        self.commits.iter().for_each(|c| f(&c.0, &c.1));
        Ok(())
    }
}

impl Names {
    /// A block carries `tx`: what its name operations do is done, as
    /// of `height`.
    fn take(&mut self, tx: &Transaction, height: u32) {
        use crate::name::NameOp;
        for op in &tx.ops {
            match op {
                NameOp::Commit { commit, memo } => self.commits.push((*commit, *memo, 100 + height as u64, height)),
                NameOp::Reveal { record, commit, .. } => {
                    self.commits.retain(|c| c.2 != *commit);
                    assert!(self.records.insert(record.name.as_bytes().to_vec(), *record).is_none());
                }
                NameOp::Update { record, .. } => {
                    let current = self.records[record.name.as_bytes()];
                    assert!(op.verify_owner(&current.owner), "not signed by the owner");
                    self.records.insert(record.name.as_bytes().to_vec(), *record);
                }
            }
        }
    }
}

fn d(n: u32) -> Digest {
    core::array::from_fn(|i| (n as u8).wrapping_add(i as u8) ^ (n >> 8) as u8)
}

/// A name is registered by a commit and then a reveal, each carried by
/// a transaction of the wallet's; what it says is changed, under a
/// fresh key each time; it is given to another wallet; and a wallet
/// made again from its phrase finds its names, and its commits.
#[test]
fn a_name_is_registered_changed_and_given() {
    use names::NameStage;
    let mut chain = Outputs::default();
    let mut names = Names::default();
    let (mut alice, phrase) = Wallet::open(MemBackend::new()).unwrap();
    alice.set_min_confirmations(1);
    let funds: Vec<Output> = (0..6).map(|_| alice.receive(10 * COIN, NOW).unwrap()).collect();
    chain.make(&funds, &mut [&mut alice]);
    // Carried by a transaction, mined: the chain's names change, the
    // chain's outputs change, and the wallet looks at both.
    fn mined(chain: &mut Outputs, alice: &mut Wallet<MemBackend>, names: &mut Names, signed: &Signed, height: u32) {
        assert!(signed.tx.verify_signatures() && signed.tx.balance() > 0);
        names.take(&signed.tx, height);
        chain.take(&signed.tx, &mut [alice]);
    }

    // What is no name, and what cannot be carried.
    assert!(matches!(alice.name_commit(b"Not A Name", d(1), NOW), Err(WalletError::Name(_))));
    assert!(matches!(alice.carry(vec![], None, &Outputs::default(), NOW), Err(WalletError::Name(_))));
    let op = alice.name_commit(b"alice", d(1), NOW).unwrap();
    assert!(matches!(alice.name_commit(b"alice", d(1), NOW), Err(WalletError::Name(_))));
    assert!(matches!(
        alice.carry(vec![op.clone()], None, &Outputs::default(), NOW),
        Err(WalletError::Insufficient { .. })
    ));
    // No transaction carried it: it is as if it had not been made.
    alice.undo_name_op(&op).unwrap();
    assert!(alice.pending_commits().is_empty());

    // The commit, carried and mined at height 10.
    let op = alice.name_commit(b"alice", d(1), NOW).unwrap();
    let signed = alice.carry(vec![op], None, &chain, NOW).unwrap();
    assert_eq!(signed.tx.ops.len(), 1);
    mined(&mut chain, &mut alice, &mut names, &signed, 10);
    assert_eq!(alice.pending_commits().len(), 1);
    // Not revealed before it has waited; nor a name there is no commit for.
    assert!(
        matches!(alice.name_reveal(b"alice", 0, 3, &names, 12, NOW), Err(WalletError::Name(m)) if m.contains("wait 1 more"))
    );
    assert!(matches!(alice.name_reveal(b"bob", 0, 3, &names, 20, NOW), Err(WalletError::Name(_))));
    let op = alice.name_reveal(b"alice", 0, 3, &names, 13, NOW).unwrap();
    assert_eq!(alice.owned_name(b"alice").unwrap().stage, NameStage::Revealed);
    assert!(alice.pending_commits().is_empty());
    // A reveal taken back goes back to its commit; made again, mined.
    let signed = alice.carry(vec![op], None, &chain, NOW).unwrap();
    alice.cancel_sent(&signed.tx.txid(), None, &chain, NOW).unwrap();
    assert!(alice.owned_name(b"alice").is_none() && alice.pending_commits().len() == 1);
    let op = alice.name_reveal(b"alice", 0, 3, &names, 13, NOW).unwrap();
    let signed = alice.carry(vec![op], None, &chain, NOW).unwrap();
    mined(&mut chain, &mut alice, &mut names, &signed, 13);
    assert_eq!(alice.sync_names(&names).unwrap(), 1);
    let owned = alice.owned_name(b"alice").unwrap();
    assert_eq!((owned.stage, owned.value, names.records[&b"alice"[..]].value), (NameStage::Owned, d(1), d(1)));
    assert_eq!(alice.sync_names(&names).unwrap(), 0);

    // Changed: what it says, and the key it is under.
    let (op, last) = alice.name_update(b"alice", d(2)).unwrap();
    assert!(!last && matches!(alice.name_update(b"alice", d(3)), Err(WalletError::Name(_))));
    let signed = alice.carry(vec![op], None, &chain, NOW).unwrap();
    mined(&mut chain, &mut alice, &mut names, &signed, 14);
    assert_eq!(alice.sync_names(&names).unwrap(), 1);
    let rotated = alice.owned_name(b"alice").unwrap();
    assert_eq!((rotated.value, rotated.used, rotated.pending), (d(2), 0, None));
    assert_ne!(rotated.nonce, owned.nonce);

    // A wallet made again from the phrase finds the name, and signs for
    // it from the other half of its key's leaves.
    let mut again = Wallet::restore(MemBackend::new(), &phrase.unwrap(), "", "").unwrap();
    assert_eq!(again.scan_names(&names, NOW).unwrap(), (1, 0));
    let found = again.owned_name(b"alice").unwrap();
    assert!(found.recovered && found.nonce == rotated.nonce && found.stage == NameStage::Owned);
    assert_eq!(again.scan_names(&names, NOW).unwrap(), (0, 0));

    // Given to another wallet: which writes the record, for the owner
    // to sign over.
    let mut bob = new();
    let record = bob.name_offer(b"alice", d(9), NOW).unwrap();
    assert_eq!(bob.owned_name(b"alice").unwrap().stage, NameStage::Offered);
    assert!(matches!(bob.name_transfer(record), Err(WalletError::Name(_))));
    let (op, _) = alice.name_transfer(record).unwrap();
    let signed = alice.carry(vec![op], None, &chain, NOW).unwrap();
    mined(&mut chain, &mut alice, &mut names, &signed, 15);
    assert_eq!((alice.sync_names(&names).unwrap(), bob.sync_names(&names).unwrap()), (1, 1));
    assert!(alice.owned_name(b"alice").is_none());
    assert_eq!(bob.owned_name(b"alice").unwrap().stage, NameStage::Owned);
    assert_eq!(reopened(&bob, "").unwrap().owned_names(), bob.owned_names());

    // A commit found by a scan is of a name not known, until it is
    // revealed by the wallet that made it.
    let op = alice.name_commit(b"second", d(4), NOW).unwrap();
    let signed = alice.carry(vec![op], None, &chain, NOW).unwrap();
    mined(&mut chain, &mut alice, &mut names, &signed, 20);
    assert_eq!(again.scan_names(&names, NOW).unwrap(), (0, 1));
    assert_eq!(again.pending_commits()[0].name, None);
    assert!(matches!(again.name_reveal(b"wrong", 0, 3, &names, 30, NOW), Err(WalletError::Name(_))));
    assert!(again.name_reveal(b"second", 0, 3, &names, 30, NOW).is_ok());
    // And one that never reached the chain is forgotten when pruned.
    alice.name_commit(b"never", d(5), NOW).unwrap();
    assert_eq!(alice.prune_commits(&names, &[]).unwrap(), ["never"]);
    assert_eq!(alice.pending_commits().len(), 1);
}

/// A wallet has an address: of its words and of which of its addresses
/// it is at. The same words opened again are at the same one; made
/// again from its words, a wallet is at one of its own, never the first
/// again; and another wallet's is another.
#[test]
fn a_wallet_has_an_address_of_its_words() {
    let (wallet, phrase) = Wallet::open(MemBackend::new()).unwrap();
    let address = wallet.address();
    assert!(address.starts_with("tab1") && address.len() == crate::address::LEN);
    assert_eq!(crate::address::decode(&address), Some(wallet.id()));
    assert_eq!((wallet.address_index(), wallet.address()), (0, address.clone()));
    assert_eq!(reopened(&wallet, "").unwrap().address(), address);
    // What it signs is its key's, and its key is what its id is of.
    let key = wallet.identity_key();
    let signed = key.sign(b"said", b"tab");
    assert!(crate::mldsa::verify(key.public_key(), b"said", b"tab", &signed));
    assert_eq!(crate::address::id_of(key.public_key()), wallet.id());
    // Made again: its own address, kept from then on.
    let restored = Wallet::restore(MemBackend::new(), &phrase.unwrap(), "", "").unwrap();
    assert!(restored.address_index() > 0);
    assert_ne!(restored.address(), address);
    assert_eq!(reopened(&restored, "").unwrap().address(), restored.address());
    let (other, _) = Wallet::open(MemBackend::new()).unwrap();
    assert_ne!(other.address(), address);
}

/// A slate sent to a wallet is kept with whom it was sent to, for as
/// long as it is pending: its answer is to be taken from that wallet
/// alone. One written to a file was sent to nobody.
#[test]
fn a_slate_is_kept_with_whom_it_was_sent_to() {
    let mut chain = Outputs::default();
    let mut wallet = funded(&mut chain, 10 * COIN);
    let (bob, mallory) = ([(7) as u8; 32], [(9) as u8; 32]);
    let to_bob = wallet.send(COIN, None, &chain, NOW).unwrap();
    wallet.send_to(&to_bob.id, &bob).unwrap();
    assert_eq!(wallet.sent_to(&to_bob.id), Some(bob));
    assert_ne!(wallet.sent_to(&to_bob.id), Some(mallory));
    // Opened again, it is still so.
    assert_eq!(reopened(&wallet, "").unwrap().sent_to(&to_bob.id), Some(bob));
    // Of a slate not sent to a wallet, and of one that is no slate of
    // this wallet's: nobody.
    assert_eq!(wallet.sent_to(&[1; 32]), None);
    // Given up, it was sent to nobody any more; and what is kept of it
    // goes when the next is sent.
    wallet.cancel_slate(&to_bob.id).unwrap();
    assert_eq!(wallet.sent_to(&to_bob.id), None);
    let again = wallet.send(COIN, None, &chain, NOW).unwrap();
    assert_eq!(wallet.sent_to(&again.id), None, "one written to a file was sent to nobody");
    wallet.send_to(&again.id, &mallory).unwrap();
    assert_eq!((wallet.sent_to(&again.id), wallet.sent_to(&to_bob.id)), (Some(mallory), None));
}

/// A wallet keeps the names it gives out under a name, signing for
/// each a certificate of a higher number than the last; and the full
/// names it is itself, so many of them, each by its newest
/// certificate. Both as they were when its file is opened again.
#[test]
fn names_under_names_are_kept() {
    use crate::subnames::{HOLDS, RENEWED, point, read};
    let mut owner = new();
    let mut alice = new();
    let unix = 1_800_000_000;
    let first = owner.give_name(b"alice", b"mailhub", &alice.id(), unix, None).unwrap();
    let checked = read(&first, unix).unwrap();
    assert_eq!((checked.full(), checked.holder, checked.by), ("alice@mailhub".to_string(), alice.id(), owner.id()));
    assert_eq!((checked.seq, checked.expires, checked.delegated), (unix, unix + HOLDS, false));
    // Again at once: a higher number. Not due again until a day on.
    let again = read(&owner.give_name(b"alice", b"mailhub", &alice.id(), unix, None).unwrap(), unix).unwrap();
    assert_eq!(again.seq, unix + 1);
    assert!(owner.names_to_renew(unix + RENEWED).is_empty());
    assert_eq!(owner.names_to_renew(unix + RENEWED + 1).len(), 1);
    assert_eq!(reopened(&owner, "").unwrap().names_given(), owner.names_given());
    assert_eq!(owner.names_given()[0].full(), "alice@mailhub");
    // Held: by the wallet it names, the newest, and so many.
    assert!(!owner.hold_name(&checked, &first, 5).unwrap(), "it names another wallet");
    assert!(alice.hold_name(&checked, &first, 5).unwrap());
    assert!(!alice.hold_name(&checked, &first, 5).unwrap(), "no newer than the one held");
    let newer = owner.give_name(b"alice", b"mailhub", &alice.id(), unix, None).unwrap();
    assert!(alice.hold_name(&read(&newer, unix).unwrap(), &newer, 5).unwrap());
    let other = owner.give_name(b"al", b"mailhub", &alice.id(), unix, None).unwrap();
    assert!(!alice.hold_name(&read(&other, unix).unwrap(), &other, 1).unwrap(), "one name is the most");
    assert!(alice.hold_name(&read(&other, unix).unwrap(), &other, 2).unwrap());
    let held = reopened(&alice, "").unwrap().names_held();
    assert_eq!(held, alice.names_held());
    assert_eq!(held.len(), 2);
    assert!(held.contains(&(point(b"alice", b"mailhub"), unix + 2, newer)));
    // By the word of a name's holder, a wallet that does not hold the
    // name signs for it: the word goes with what it signs.
    let mut signer = new();
    let word = crate::subnames::delegate(&owner.identity_key(), b"mailhub", &signer.id(), unix + 86_400);
    signer.sign_for(b"mailhub", &word).unwrap();
    assert_eq!(reopened(&signer, "").unwrap().signs_for(b"mailhub"), Some(&word[..]));
    assert_eq!((signer.signs_for(b"mailhut"), signer.signs_for_all().len()), (None, 1));
    let by_word = signer
        .give_name(b"carol", b"mailhub", &alice.id(), unix, signer.signs_for(b"mailhub").map(<[u8]>::to_vec).as_deref())
        .unwrap();
    let carol = read(&by_word, unix).unwrap();
    assert_eq!((carol.by, carol.delegated, carol.expires), (owner.id(), true, unix + 86_400));
    // Let go of, on either side.
    assert!(alice.drop_name(b"alice", b"mailhub").unwrap() && !alice.drop_name(b"alice", b"mailhub").unwrap());
    assert!(owner.take_name_back(b"al", b"mailhub").unwrap() && !owner.take_name_back(b"al", b"mailhub").unwrap());
    assert_eq!((alice.names_held().len(), owner.names_given().len()), (1, 1));
}

/// A payment says what it is for, and is receipted: the slate carries
/// a note to the wallet that is paid, which answers with its word that
/// the output is its own; the wallet that pays signs only with that,
/// and keeps what will prove the payment, which holds once the block
/// that made the output is known. And coins are burned, for whoever
/// the burn says.
#[test]
fn payments_are_receipted_and_kept_to_be_proven() {
    use crate::proofs::{Beneficiary, Burn, Claim, sender_tag};
    use crate::store::sparse::empty;
    use crate::store::state::{STATE_HEIGHT, root_of_state_path as root_of_path};
    let mut chain = Outputs::default();
    let mut alice = funded(&mut chain, 10 * COIN);
    let mut bob = new();
    let slate = alice.send_noted(COIN, None, b"deposit 4821", &chain, NOW).unwrap();
    assert_eq!((&slate.note[..], slate.receipt.as_ref()), (&b"deposit 4821"[..], None));
    // As text and back, before it is answered and after.
    assert_eq!(Slate::from_text(&slate.to_text()), Some(slate.clone()));
    let mut answered = slate.clone();
    bob.receive_slate(&mut answered, NOW).unwrap();
    assert_eq!(Slate::from_text(&answered.to_text()), Some(answered.clone()));
    let receipt = answered.receipt.clone().unwrap();
    assert_eq!(receipt.recipient(), bob.id());
    let paid = answered.outputs.last().unwrap().clone();
    assert_eq!(bob.note_of(&paid.commitment), Some(&b"deposit 4821"[..]));
    // Nothing of Alice's address is in it: only the hash of a secret.
    assert_ne!(slate.sender, alice.id());
    // Not signed without the receipt, nor with one for another note, or
    // by another wallet for another output.
    let without = Slate { receipt: None, stage: 1, ..answered.clone() };
    assert!(alice.finalize(&without, NOW).is_err());
    let other_note = Slate { note: b"deposit 1".to_vec(), ..answered.clone() };
    let forged = crate::proofs::Receipt::sign(&bob.identity_key(), &paid, &slate.id, &slate.sender, b"deposit 1");
    let forged = Slate { receipt: Some(forged), ..other_note };
    assert!(matches!(alice.finalize(&forged, NOW), Err(WalletError::BadSlate("no receipt for this payment"))));
    let signed = alice.finalize(&answered, NOW).unwrap();
    // Kept, and not yet proven: no block has it.
    let kept = alice.payments();
    assert_eq!((kept.len(), kept[0].txid, kept[0].proven, kept[0].landed), (1, signed.tx.txid(), false, None));
    assert!(alice.payments_to_prove().is_empty());
    let Claim::Payment { secret, slate: of, note, receipt: held, payer } = kept[0].proof.claim.clone() else {
        panic!()
    };
    assert_eq!((of, &note[..], held), (slate.id, &b"deposit 4821"[..], receipt));
    // (Whose the payment is: Alice's address, by her own word, and by
    // the tag the slate carried, which is of her address and a secret.)
    assert_eq!((payer.recipient(), sender_tag(&alice.id(), &secret)), (alice.id(), slate.sender));
    // A block takes it: where its output is, is known, and its path
    // is asked for. (Here the state is that output alone.)
    chain.take(&signed.tx, &mut [&mut alice, &mut bob]);
    let due = alice.payments_to_prove();
    assert_eq!(due.len(), 1);
    let (txid, height, position) = due[0];
    let mut path = [[0; 32]; STATE_HEIGHT];
    path[..STATE_HEIGHT - 1].iter_mut().enumerate().for_each(|(level, sibling)| *sibling = *empty(level));
    path[STATE_HEIGHT - 1] = crate::store::names::empty_root();
    assert!(alice.prove_payment(&txid, height, position, &paid.memo, path).unwrap());
    let proven = reopened(&alice, "").unwrap().payments();
    assert_eq!(proven, alice.payments());
    assert!(proven[0].proven && alice.payments_to_prove().is_empty());
    let leaf = crate::output::output_leaf(&paid.commitment, &paid.memo, paid.amount, height);
    assert_eq!(proven[0].proof.check(&root_of_path(position, &leaf, &path)), Ok(()));
    // Burned: nobody's to spend, and to the credit of whom it says.
    let burn =
        Burn { beneficiary: Beneficiary::Name("alice@mailhub".into()), nonce: [5; 32], purpose: "a year".into() };
    let held = alice.balance(&chain).unwrap();
    let burned = alice.burn(2 * COIN, None, burn.clone(), &chain, NOW).unwrap();
    let gone = burned.tx.outputs.last().unwrap();
    assert_eq!((gone.key_hash, gone.amount, gone.memo), (crate::proofs::BURN_KEY_HASH, 2 * COIN, burn.memo()));
    chain.take(&burned.tx, &mut [&mut alice]);
    let all = alice.payments();
    assert_eq!((all.len(), alice.payments_to_prove().len()), (2, 1));
    assert!(all.iter().any(|p| p.proof.claim == Claim::Burn(burn.clone())));
    assert!(alice.balance(&chain).unwrap().confirmed < held.confirmed - 2 * COIN as u128 + 1);
    // Another's memo at that position is not this burn: nothing is kept.
    let (txid, height, position) = alice.payments_to_prove()[0];
    assert!(!alice.prove_payment(&txid, height, position, &[1; 20], path).unwrap());
    assert!(alice.payments_to_prove().is_empty());
}

/// The chain goes over to a branch on which what a payment spends lies
/// elsewhere. Where an output lies is signed, so the payment spends
/// nothing there: the wallet's list says it is to be made again, it is
/// not sent again as it was, and taking it back frees what it was to
/// spend, from where that now is.
#[test]
fn a_payment_whose_input_moved_is_to_be_made_again() {
    use super::list::{Kind, Stage};
    let mut chain = Outputs::default();
    let mut alice = funded(&mut chain, 100 * COIN);
    let mut bob = new();
    let mut slate = alice.send(30 * COIN, None, &chain, NOW).unwrap();
    bob.receive_slate(&mut slate, NOW).unwrap();
    let signed = alice.finalize(&slate, NOW).unwrap();
    let stages = |w: &Wallet<MemBackend>| w.list().iter().map(|r| (r.kind, r.stage)).collect::<Vec<_>>();
    assert_eq!(stages(&alice), [(Kind::Sent, Stage::Pooled)]);
    assert_eq!(signed.tx.spent_positions(), [0]);

    // The other branch makes her output after another's.
    let hers = chain.0[0];
    chain.0 = vec![([7; 32], hers.1, 1, true), hers];
    alice.locate(1, &[hers.0], 1, &[0; 32], 2).unwrap();
    assert_eq!(alice.reconcile(&chain, 5, 10, Some(0)).unwrap(), Reconciled::default());
    // What she has is what the chain has: all of it locked in the
    // payment, none of it lost.
    let b = alice.balance(&chain).unwrap();
    assert_eq!((b.locked, b.lost, b.confirmed), (100 * COIN as u128, 0, 0));
    assert_eq!(stages(&alice)[0], (Kind::Sent, Stage::Remake));
    assert!(alice.resend(&signed.tx.txid()).is_err());

    // Taken back: signed for where the output now is, and mined.
    let back = alice.cancel_sent(&signed.tx.txid(), None, &chain, NOW).unwrap();
    assert_eq!(back.tx.spent_positions(), [1]);
    let rows = alice.list().to_vec();
    assert_eq!((rows[0].stage, rows[0].by), (Stage::Replaced, 2));
    assert_eq!((rows[1].kind, rows[1].stage, rows[1].of), (Kind::Cancel, Stage::Pooled, 1));
    chain.take(&back.tx, &mut [&mut alice]);
    alice.reconcile(&chain, 6, 10, None).unwrap();
    let b = alice.balance(&chain).unwrap();
    assert_eq!((b.locked, b.confirmed), (0, (100 * COIN - back.tx.balance() as u64) as u128));
    assert_eq!(alice.list()[1].stage, Stage::Confirmed);
    // The list is there, as it was, when the file is opened again.
    assert_eq!(reopened(&alice, "").unwrap().list(), alice.list());
}
