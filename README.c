//Turtle_TRUSTNOONE


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sodium.h>

#define PUBKEY_SZ crypto_sign_PUBLICKEYBYTES
#define PRIVKEY_SZ crypto_sign_SECRETKEYBYTES
#define SIGNATURE_SZ crypto_sign_BYTES
#define HASH_SZ 64
#define TXID_SZ 8
#define MAX_SIGNATURES 16
#define EXPIRY_WINDOW 5
#define MAX_HASH_LOG 256
#define MAX_TRANSACTIONS_PER_BLOCK 128

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

typedef struct {
    unsigned char prev_block_hash[HASH_SZ];
    unsigned char merkle_root[HASH_SZ];
    uint64_t timestamp;
    uint32_t block_height;
    uint32_t nonce;
    unsigned char proposer_pubkey[PUBKEY_SZ];
    unsigned char signature[SIGNATURE_SZ];
} BlockHeader;

typedef struct {
    BlockHeader header;
    Transaction transactions[MAX_TRANSACTIONS_PER_BLOCK];
    size_t tx_count;
} Block;

// === Helpers endian R ===
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

// === Compute Transaction Hash ===
bool compute_tx_hash(const Transaction *tx, unsigned char *hash_out) {
    unsigned char *buf = sodium_malloc(512);
    if (!buf) return false;
    size_t offset = 0;
    memcpy(buf + offset, &tx->tx_version, sizeof(tx->tx_version)); offset += sizeof(tx->tx_version);
    memcpy(buf + offset, tx->from_addr, PUBKEY_SZ); offset += PUBKEY_SZ;
    memcpy(buf + offset, tx->to_addr, 32); offset += 32;
    write_le64(buf, &offset, tx->amount_atomic);
    write_le32(buf, &offset, tx->nonce);
    write_le32(buf, &offset, tx->expiry);
    bool res = crypto_generichash(hash_out, HASH_SZ, buf, offset, NULL, 0) == 0;
    sodium_memzero(buf, 512);
    sodium_free(buf);
    return res;
}

// === Comp Merkle Root (simp bin hash tree) ===
void compute_merkle_root(Transaction *txs, size_t tx_count, unsigned char *out_root) {
    if (tx_count == 0) {
        memset(out_root, 0, HASH_SZ);
        return;
    }
    unsigned char hashes[MAX_TRANSACTIONS_PER_BLOCK][HASH_SZ];
    for (size_t i = 0; i < tx_count; i++) {
        compute_tx_hash(&txs[i], hashes[i]);
    }

    size_t count = tx_count;
    while (count > 1) {
        size_t new_count = (count + 1) / 2;
        for (size_t i = 0; i < new_count; i++) {
            unsigned char buf[HASH_SZ * 2];
            memcpy(buf, hashes[i * 2], HASH_SZ);
            if (i * 2 + 1 < count) {
                memcpy(buf + HASH_SZ, hashes[i * 2 + 1], HASH_SZ);
            } else {
                memcpy(buf + HASH_SZ, hashes[i * 2], HASH_SZ);
            }
            crypto_generichash(hashes[i], HASH_SZ, buf, HASH_SZ * 2, NULL, 0);
        }
        count = new_count;
    }
    memcpy(out_root, hashes[0], HASH_SZ);
}

// === Comp Blockhead Hash ===
bool compute_block_hash(const BlockHeader *header, unsigned char *out_hash) {
    unsigned char buf[512];
    size_t offset = 0;
    memcpy(buf + offset, header->prev_block_hash, HASH_SZ); offset += HASH_SZ;
    memcpy(buf + offset, header->merkle_root, HASH_SZ); offset += HASH_SZ;
    write_le64(buf, &offset, header->timestamp);
    write_le32(buf, &offset, header->block_height);
    write_le32(buf, &offset, header->nonce);
    memcpy(buf + offset, header->proposer_pubkey, PUBKEY_SZ); offset += PUBKEY_SZ;
    return crypto_generichash(out_hash, HASH_SZ, buf, offset, NULL, 0) == 0;
}

// === Val inst Trans ===
bool is_valid(const Transaction *tx, uint32_t current_nonce, uint32_t current_block,
              const unsigned char authorized_pubkeys[][PUBKEY_SZ], int authorized_count, int required_signers) {
    // Basic checks: nonce, exp, val
    if (tx->nonce != current_nonce + 1) return false;
    if (tx->expiry + EXPIRY_WINDOW < current_block) return false;
    if (tx->amount_atomic == 0 || tx->amount_atomic > UINT64_MAX / 2) return false;

    // Gen hash & auth sigs
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
        if (!sig_valid) return false;
    }
    return valid >= required_signers;
}

// === Validate Block ===
bool validate_block(const Block *block, const unsigned char *expected_prev_hash,
                    const unsigned char authorized_validators[][PUBKEY_SZ], int validator_count) {
    // Check prev hash
    if (memcmp(block->header.prev_block_hash, expected_prev_hash, HASH_SZ) != 0) {
        fprintf(stderr, "❌ Previous hash mismatch\n");
        return false;
    }

    // Ver proposer = auth
    bool authorized = false;
    for (int i = 0; i < validator_count; i++) {
        if (memcmp(block->header.proposer_pubkey, authorized_validators[i], PUBKEY_SZ) == 0) {
            authorized = true;
            break;
        }
    }
    if (!authorized) {
        fprintf(stderr, "❌ Unauthorized proposer\n");
        return false;
    }

    // Ver block sig
    unsigned char block_hash[HASH_SZ];
    if (!compute_block_hash(&block->header, block_hash)) return false;
    if (crypto_sign_verify_detached(block->header.signature, block_hash, HASH_SZ, block->header.proposer_pubkey) != 0) {
        fprintf(stderr, "❌ Invalid block signature\n");
        return false;
    }

    // Ver Merkle root
    unsigned char merkle_root[HASH_SZ];
    compute_merkle_root((Transaction *)block->transactions, block->tx_count, merkle_root);
    if (memcmp(merkle_root, block->header.merkle_root, HASH_SZ) != 0) {
        fprintf(stderr, "❌ Merkle root mismatch\n");
        return false;
    }

    // Val trans (example w dummy nonce, replace with real state)
    uint32_t last_nonce = 0;
    uint32_t current_block_height = block->header.block_height;
    for (size_t i = 0; i < block->tx_count; i++) {
        if (!is_valid(&block->transactions[i], last_nonce, current_block_height,
                      authorized_validators, validator_count, 2)) {
            fprintf(stderr, "❌ Transaction %zu invalid\n", i);
            return false;
        }
        last_nonce = block->transactions[i].nonce;
    }

    return true;
}

// === Simplified ledger persistence (append block to file) ===
bool save_block(const Block *block, const char *filename) {
    FILE *f = fopen(filename, "ab");
    if (!f) return false;
    fwrite(&block->header, sizeof(BlockHeader), 1, f);
    fwrite(block->transactions, sizeof(Transaction), block->tx_count, f);
    fclose(f);
    return true;
}

// === Ex. Main Flow ===
int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    printf("🔐 Blockchain node starting...\n");

    // Setup keys for two auth validators
    unsigned char validator1_pub[PUBKEY_SZ], validator1_priv[PRIVKEY_SZ];
    unsigned char validator2_pub[PUBKEY_SZ], validator2_priv[PRIVKEY_SZ];
    crypto_sign_keypair(validator1_pub, validator1_priv);
    crypto_sign_keypair(validator2_pub, validator2_priv);

    unsigned char authorized_validators[2][PUBKEY_SZ];
    memcpy(authorized_validators[0], validator1_pub, PUBKEY_SZ);
    memcpy(authorized_validators[1], validator2_pub, PUBKEY_SZ);

    // Create genesis block with dummy prev hash of zips
    Block genesis = {0};
    memset(genesis.header.prev_block_hash, 0, HASH_SZ);
    genesis.header.block_height = 0;
    genesis.header.timestamp = (uint64_t)time(NULL);
    genesis.header.nonce = 0;
    memcpy(genesis.header.proposer_pubkey, validator1_pub, PUBKEY_SZ);
    genesis.tx_count = 0;
    compute_merkle_root(genesis.transactions, 0, genesis.header.merkle_root);

    unsigned char genesis_hash[HASH_SZ];
    compute_block_hash(&genesis.header, genesis_hash);
    crypto_sign_detached(genesis.header.signature, NULL, genesis_hash, HASH_SZ, validator1_priv);

    if (!validate_block(&genesis, genesis.header.prev_block_hash, authorized_validators, 2)) {
        fprintf(stderr, "Genesis block validation failed\n");
        return 1;
    }
    save_block(&genesis, "blockchain.dat");
    printf("✅ Genesis block created and saved\n");

    // Spawn new block w/ transactions
    Block new_block = {0};
    memcpy(new_block.header.prev_block_hash, genesis_hash, HASH_SZ);
    new_block.header.block_height = 1;
    new_block.header.timestamp = (uint64_t)time(NULL);
    memcpy(new_block.header.proposer_pubkey, validator2_pub, PUBKEY_SZ);

    // Create a dummy trans
    Transaction tx = {0};
    tx.tx_version = 1;
    memcpy(tx.from_addr, validator1_pub, PUBKEY_SZ);
    randombytes_buf(tx.to_addr, 32);
    tx.amount_atomic = 1000000;
    tx.nonce = 1;
