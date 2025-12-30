#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_must_use,
    non_snake_case
)]
use crate::internal;
use bitcoin::opcodes::all as opcodes;
use bitcoin::hashes::Hash;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::script::{Builder, ScriptBuf, ScriptHash};
use bitcoin::secp256k1::{PublicKey as secp256k1PublicKey, Scalar, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::PublicKey;
use bitcoin::{Block, OutPoint, PubkeyHash, Sequence, Transaction, TxIn, TxOut, Witness};
use internal::key_utils::{
    add_privkeys, add_pubkeys, hash_pubkeys, privkey_multipication_tweak, pubkey_from_secret,
    pubkey_multipication_tweak,
};
use internal::script_utils::{build_htlc_offerer_witness_script, p2wpkh_output_script};
use internal::tx_utils::{build_output, build_transaction};

//
// Exercise 1
//

pub fn two_of_two_multisig_witness_script(pubkey1: &PublicKey, pubkey2: &PublicKey) -> ScriptBuf {
    let keys = [*pubkey1, *pubkey2];

    bitcoin::script::Builder::new()
        .push_int(2)
        .push_key(&keys[0])
        .push_key(&keys[1])
        .push_int(2)
        .push_opcode(opcodes::OP_CHECKMULTISIG)
        .into_script()
}

//
// Exercise 2
//

pub fn build_funding_transaction(
    txins: Vec<TxIn>,
    alice_pubkey: &PublicKey,
    bob_pubkey: &PublicKey,
    amount: u64,
) -> Transaction {
    let witness_script = two_of_two_multisig_witness_script(alice_pubkey, bob_pubkey);
    let p2wsh_script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
    let output = build_output(amount, p2wsh_script_pubkey);
    build_transaction(Version::TWO, LockTime::ZERO, txins, vec![output])
}

//
// Exercise 3
//

pub fn build_refund_transaction(
    funding_txin: TxIn,
    alice_pubkey: PublicKey,
    bob_pubkey: PublicKey,
    alice_balance: u64,
    bob_balance: u64,
) -> Transaction {
    let alice_script = p2wpkh_output_script(alice_pubkey);
    let bob_script = p2wpkh_output_script(bob_pubkey);

    let alice_output = build_output(alice_balance, alice_script);
    let bob_output = build_output(bob_balance, bob_script);

    let mut outputs = vec![alice_output, bob_output];
    outputs.sort_by(|a, b| {
        a.value.cmp(&b.value).then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
    });

    build_transaction(Version::TWO, LockTime::ZERO, vec![funding_txin], outputs)
}

//
// Exercise 4
//

pub fn generate_revocation_pubkey(
    countersignatory_basepoint: secp256k1PublicKey,
    per_commitment_point: secp256k1PublicKey,
) -> secp256k1PublicKey {
    let tweak1 = hash_pubkeys(countersignatory_basepoint, per_commitment_point);
    let tweak2 = hash_pubkeys(per_commitment_point, countersignatory_basepoint);

    let p1 = pubkey_multipication_tweak(countersignatory_basepoint, tweak1);
    let p2 = pubkey_multipication_tweak(per_commitment_point, tweak2);

    add_pubkeys(p1, p2)
}

//
// Exercise 5
//

pub fn generate_revocation_privkey(
    countersignatory_per_commitment_secret: SecretKey,
    revocation_base_secret: SecretKey,
) -> SecretKey {
    let base_point = pubkey_from_secret(revocation_base_secret);
    let per_commitment_point = pubkey_from_secret(countersignatory_per_commitment_secret);

    let tweak1 = hash_pubkeys(base_point, per_commitment_point);
    let tweak2 = hash_pubkeys(per_commitment_point, base_point);

    let sk1 = privkey_multipication_tweak(revocation_base_secret, tweak1);
    let sk2 = privkey_multipication_tweak(countersignatory_per_commitment_secret, tweak2);

    add_privkeys(sk1, sk2)
}

//
// Exercise 6
//

pub fn to_local(
    revocation_key: &PublicKey,
    to_local_delayed_pubkey: &PublicKey,
    to_self_delay: i64,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(opcodes::OP_IF)
        .push_key(revocation_key)
        .push_opcode(opcodes::OP_ELSE)
        .push_int(to_self_delay)
        .push_opcode(opcodes::OP_CSV)
        .push_opcode(opcodes::OP_DROP)
        .push_key(to_local_delayed_pubkey)
        .push_opcode(opcodes::OP_ENDIF)
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script()
}

//
// Exercise 7
//

pub fn build_commitment_transaction(
    funding_txin: TxIn,
    revocation_pubkey: &PublicKey,
    to_local_delayed_pubkey: &PublicKey,
    remote_pubkey: PublicKey,
    to_self_delay: i64,
    local_amount: u64,
    remote_amount: u64,
) -> Transaction {
    let to_local_script = to_local(revocation_pubkey, to_local_delayed_pubkey, to_self_delay);
    let to_local_p2wsh = ScriptBuf::new_p2wsh(&to_local_script.wscript_hash());
    let local_output = build_output(local_amount, to_local_p2wsh);

    let remote_script = p2wpkh_output_script(remote_pubkey);
    let remote_output = build_output(remote_amount, remote_script);

    let mut outputs = vec![local_output, remote_output];
    outputs.sort_by(|a, b| {
        a.value.cmp(&b.value).then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
    });

    build_transaction(Version::TWO, LockTime::ZERO, vec![funding_txin], outputs)
}

//
// Exercise 8
//

pub fn build_htlc_commitment_transaction(
    funding_txin: TxIn,
    revocation_pubkey: &PublicKey,
    remote_htlc_pubkey: &PublicKey,
    local_htlc_pubkey: &PublicKey,
    to_local_delayed_pubkey: &PublicKey,
    remote_pubkey: PublicKey,
    to_self_delay: i64,
    payment_hash160: &[u8; 20],
    htlc_amount: u64,
    local_amount: u64,
    remote_amount: u64,
) -> Transaction {
    let to_local_script = to_local(revocation_pubkey, to_local_delayed_pubkey, to_self_delay);
    let to_local_p2wsh = ScriptBuf::new_p2wsh(&to_local_script.wscript_hash());
    let local_output = build_output(local_amount, to_local_p2wsh);

    let remote_script = p2wpkh_output_script(remote_pubkey);
    let remote_output = build_output(remote_amount, remote_script);

    let htlc_script = build_htlc_offerer_witness_script(
        revocation_pubkey, 
        remote_htlc_pubkey, 
        local_htlc_pubkey, 
        payment_hash160
    );

    let htlc_p2wsh = ScriptBuf::new_p2wsh(&htlc_script.wscript_hash());
    let htlc_output = build_output(htlc_amount, htlc_p2wsh);

    let mut outputs = vec![local_output, remote_output, htlc_output];
    outputs.sort_by(|a, b| {
        a.value.cmp(&b.value).then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
    });

    build_transaction(Version::TWO, LockTime::ZERO, vec![funding_txin], outputs)
}

//
// Exercise 9
//

pub fn build_htlc_timeout_transaction(
    htlc_txin: TxIn,
    revocation_pubkey: &PublicKey,
    to_local_delayed_pubkey: &PublicKey,
    to_self_delay: i64,
    cltv_expiry: u32,
    htlc_amount: u64,
) -> Transaction {
    let to_local_script = to_local(revocation_pubkey, to_local_delayed_pubkey, to_self_delay);
    let to_local_p2wsh = ScriptBuf::new_p2wsh(&to_local_script.wscript_hash());
    let output = build_output(htlc_amount, to_local_p2wsh);

    let mut tx = build_transaction(Version::TWO, LockTime::ZERO, vec![htlc_txin], vec![output]);
    tx.lock_time = LockTime::from_consensus(cltv_expiry);
    tx
}