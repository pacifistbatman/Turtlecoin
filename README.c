//Turtle_TRUSTNOONE


#include <stdio.h>
#include <stdbool.h>
#include <sodium.h>
#include <stdint.h>
#include <string.h>

#define PUBKEY_SZ crypto_sign_PUBLICKEYBYTES
#define PRIVKEY_SZ crypto_sign_SECRETKEYBYTES
#define SIGNATURE_SZ crypto_sign_BYTES
#define HASH_SZ 64
#define TXID_SZ 8
#define MAX_SIGNATURES 16
#define EXPIRY_WINDOW 5
#define MAX_HASH_LOG 256

#pragma pack(push, 1)
typedef struct {
    uint8_t tx_version;
    unsigned char from_addr[PUBKEY_SZ];
    unsigned char to_addr[32];
    uint64_t amount_atomic;
    uint32_t nonce;
    uint32_t expiry;
    int32_t signature_count;
    unsigned char signatures[MAX_SIGNATURES][SIGNATURE_SZ];
} Transaction;
#pragma pack(pop)

unsigned char seen_hashes[MAX_HASH_LOG][HASH_SZ];
int seen_hash_count = 0;

// Serialization helpers
void write_le32(unsigned char *buf, size_t *offset, uint32_t val) {
    val = htole32(val);
    memcpy(buf + *offset, &val, sizeof(uint32_t));
    *offset += sizeof(uint32_t);
}
void write_le64(unsigned char *buf, size_t *offset, uint64_t val) {
    val = htole64(val);
    memcpy(buf + *offset, &val, sizeof(uint64_t));
    *offset += sizeof(uint64_t);
}

// Canonical transaction hash
bool compute_tx_hash(const Transaction *tx, unsigned char *hash_out) {
    unsigned char *buf = sodium_malloc(512);
    if (!buf) {
        fprintf(stderr, "❌ Failed to allocate hash buffer\n");
        return false;
    }

    size_t offset = 0;
    memcpy(buf + offset, &tx->tx_version, sizeof(tx->tx_version)); offset += sizeof(tx->tx_version);
    memcpy(buf + offset, tx->from_addr, PUBKEY_SZ); offset += PUBKEY_SZ;
    memcpy(buf + offset, tx->to_addr, 32); offset += 32;
    write_le64(buf, &offset, tx->amount_atomic);
    write_le32(buf, &offset, tx->nonce);
    write_le32(buf, &offset, tx->expiry);

    if (crypto_generichash(hash_out, HASH_SZ, buf, offset, NULL, 0) != 0) {
        sodium_memzero(buf, 512);
        sodium_free(buf);
        fprintf(stderr, "❌ Hashing failed\n");
        return false;
    }

    sodium_memzero(buf, 512);
    sodium_free(buf);
    return true;
}

// Truncated txid for audit display
void txid_from_hash(const unsigned char *hash, unsigned char *txid_out) {
    memcpy(txid_out, hash, TXID_SZ);
}

// In-memory replay protection
bool already_seen(const unsigned char *hash) {
    for (int i = 0; i < seen_hash_count; i++) {
        if (sodium_memcmp(seen_hashes[i], hash, HASH_SZ) == 0) return true;
    }
    return false;
}

void log_seen(const unsigned char *hash) {
    if (seen_hash_count < MAX_HASH_LOG) {
        memcpy(seen_hashes[seen_hash_count++], hash, HASH_SZ);
    }
}

// Verifies signatures using authorized pubkeys
bool verify_signatures(const Transaction *tx, const unsigned char authorized_pubkeys[][PUBKEY_SZ],
                       int authorized_count, int required_signers) {
    if (tx->signature_count != required_signers || tx->signature_count > MAX_SIGNATURES) {
        fprintf(stderr, "❌ Invalid signature count\n");
        return false;
    }

    unsigned char hash[HASH_SZ];
    if (!compute_tx_hash(tx, hash)) return false;

    bool used[authorized_count];
    memset(used, 0, sizeof(used));
    int valid = 0;

    for (int i = 0; i < tx->signature_count; i++) {
        bool sig_valid = false;
        for (int j = 0; j < authorized_count; j++) {
            if (used[j]) continue;
            if (crypto_sign_verify_detached(tx->signatures[i], hash, HASH_SZ, authorized_pubkeys[j]) == 0) {
                used[j] = true;
                valid++;
                sig_valid = true;
                break;
            }
        }
        if (!sig_valid) break;
    }

    sodium_memzero(hash, HASH_SZ);
    return valid >= required_signers;
}

// Full validation pipeline
bool is_valid(const Transaction *tx, uint32_t current_nonce, uint32_t current_block,
              const unsigned char authorized_pubkeys[][PUBKEY_SZ], int authorized_count, int required_signers) {

    if (tx->nonce != current_nonce + 1) {
        fprintf(stderr, "❌ Nonce mismatch\n");
        return false;
    }

    if (tx->expiry + EXPIRY_WINDOW < current_block) {
        fprintf(stderr, "❌ Transaction expired\n");
        return false;
    }

    if (tx->amount_atomic == 0 || tx->amount_atomic > UINT64_MAX / 2) {
        fprintf(stderr, "❌ Invalid amount\n");
        return false;
    }

    unsigned char hash[HASH_SZ];
    if (!compute_tx_hash(tx, hash)) return false;

    unsigned char txid[TXID_SZ];
    txid_from_hash(hash, txid);
    printf("🔎 txid: ");
    for (int i = 0; i < TXID_SZ; i++) printf("%02X", txid[i]);
    printf("\n");

    if (already_seen(hash)) {
        fprintf(stderr, "⚠️ Replay detected\n");
        return false;
    }

    if (!verify_signatures(tx, authorized_pubkeys, authorized_count, required_signers)) {
        fprintf(stderr, "❌ Signature validation failed\n");
        return false;
    }

    log_seen(hash);
    return true;
}

// Prints hex public key
void print_keypair(unsigned char *pub, unsigned char *priv, const char *label) {
    crypto_sign_keypair(pub, priv);
    printf("🔑 %s public key: ", label);
    for (int i = 0; i < PUBKEY_SZ; i++) printf("%02X", pub[i]);
    printf("\n");
}

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "🧂 libsodium init failed\n");
        return 1;
    }

    printf("🔐 Turtle_TRUSTNOONE audit mode engaged\n");

    unsigned char sender_pub[PUBKEY_SZ], sender_priv[PRIVKEY_SZ];
    unsigned char approver_pub[PUBKEY_SZ], approver_priv[PRIVKEY_SZ];

    print_keypair(sender_pub, sender_priv, "Sender");
    print_keypair(approver_pub, approver_priv, "Approver");

    Transaction tx = {0};
    tx.tx_version = 1;
    memcpy(tx.from_addr, sender_pub, PUBKEY_SZ);
    randombytes_buf(tx.to_addr, 32); // fake recipient
    tx.amount_atomic = 1000000;
    tx.nonce = 7;
    tx.expiry = 500;
    tx.signature_count = 2;

    unsigned char hash[HASH_SZ];
    if (!compute_tx_hash(&tx, hash)) return 1;

    if (crypto_sign_detached(tx.signatures[0], NULL, hash, HASH_SZ, sender_priv) != 0 ||
        crypto_sign_detached(tx.signatures[1], NULL, hash, HASH_SZ, approver_priv) != 0) {
        fprintf(stderr, "❌ Signature failure\n");
        return 1;
    }

    unsigned char authorized_keys[2][PUBKEY_SZ];
    memcpy(authorized_keys[0], sender_pub, PUBKEY_SZ);
    memcpy(authorized_keys[1], approver_pub, PUBKEY_SZ);

    if (is_valid(&tx, 6, 499, authorized_keys, 2, 2)) {
        printf("✅ Transaction is valid\n");
    } else {
        printf("❌ Transaction failed validation\n");
    }

    return 0;
}
