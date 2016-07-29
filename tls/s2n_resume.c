/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_resume.h"
#include "tls/s2n_crypto.h"

int s2n_is_caching_enabled(struct s2n_config *config)
{
    /* Caching is enabled iff all of the caching callbacks are set */
    return config->cache_store && config->cache_retrieve && config->cache_delete;
}

static int s2n_serialize_resumption_state(struct s2n_connection *conn, struct s2n_stuffer *to)
{
    uint64_t now;

    if (s2n_stuffer_space_remaining(to) < S2N_STATE_SIZE_IN_BYTES) {
        return -1;
    }

    /* Get the time */
    GUARD(conn->config->nanoseconds_since_epoch(conn->config->data_for_nanoseconds_since_epoch, &now));

    /* Write the entry */
    GUARD(s2n_stuffer_write_uint8(to, S2N_SERIALIZED_FORMAT_VERSION));
    GUARD(s2n_stuffer_write_uint8(to, conn->actual_protocol_version));
    GUARD(s2n_stuffer_write_bytes(to, conn->secure.cipher_suite->value, S2N_TLS_CIPHER_SUITE_LEN));
    GUARD(s2n_stuffer_write_uint64(to, now));
    GUARD(s2n_stuffer_write_bytes(to, conn->secure.master_secret, S2N_TLS_SECRET_LEN));

    return 0;
}

static int s2n_deserialize_resumption_state(struct s2n_connection *conn, struct s2n_stuffer *from)
{
    uint64_t now, then;
    uint8_t format;
    uint8_t protocol_version;
    uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN];

    if (s2n_stuffer_data_available(from) < S2N_STATE_SIZE_IN_BYTES) {
        return -1;
    }

    GUARD(s2n_stuffer_read_uint8(from, &format));
    if (format != S2N_SERIALIZED_FORMAT_VERSION) {
        return -1;
    }

    GUARD(s2n_stuffer_read_uint8(from, &protocol_version));
    if (protocol_version != conn->actual_protocol_version) {
        return -1;
    }

    GUARD(s2n_stuffer_read_bytes(from, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN));
    if (memcmp(conn->secure.cipher_suite->value, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN)) {
        return -1;
    }

    GUARD(conn->config->nanoseconds_since_epoch(conn->config->data_for_nanoseconds_since_epoch, &now));

    GUARD(s2n_stuffer_read_uint64(from, &then));
    if (then > now) {
        return -1;
    }
    if (now - then > S2N_STATE_LIFETIME_IN_NANOS) {
        return -1;
    }

    /* Last but not least, put the master secret in place */
    GUARD(s2n_stuffer_read_bytes(from, conn->secure.master_secret, S2N_TLS_SECRET_LEN));

    return 0;
}

int s2n_resume_from_cache(struct s2n_connection *conn)
{
    uint8_t data[S2N_STATE_SIZE_IN_BYTES];
    struct s2n_blob entry = { .data = data, .size = S2N_STATE_SIZE_IN_BYTES };
    struct s2n_stuffer from;
    uint64_t size;

    if (conn->session_id_len == 0 || conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN) {
        return -1;
    }

    GUARD(s2n_stuffer_init(&from, &entry));
    uint8_t *state = s2n_stuffer_raw_write(&from, entry.size);
    notnull_check(state);

    size = S2N_STATE_SIZE_IN_BYTES;
    if (conn->config->cache_retrieve(conn->config->cache_retrieve_data, conn->session_id, conn->session_id_len, state, &size)) {
        return -1;
    }

    if (size != S2N_STATE_SIZE_IN_BYTES) {
        return -1;
    }

    GUARD(s2n_deserialize_resumption_state(conn, &from));

    return 0;
}

int s2n_store_to_cache(struct s2n_connection *conn)
{
    uint8_t data[S2N_STATE_SIZE_IN_BYTES];
    struct s2n_blob entry = { .data = data, .size = S2N_STATE_SIZE_IN_BYTES };
    struct s2n_stuffer to;

    if (!s2n_is_caching_enabled(conn->config)) {
        return -1;
    }

    if (conn->session_id_len == 0 || conn->session_id_len > S2N_TLS_SESSION_ID_MAX_LEN) {
        return -1;
    }

    GUARD(s2n_stuffer_init(&to, &entry));
    GUARD(s2n_serialize_resumption_state(conn, &to));

    /* Store to the cache */
    conn->config->cache_store(conn->config->cache_store_data, S2N_TLS_SESSION_CACHE_TTL, conn->session_id, conn->session_id_len, entry.data, entry.size);

    return 0;
}

int s2n_get_valid_ticket_key(struct s2n_config *config, struct s2n_ticket_key *key)
{
    if (config->num_prepped_ticket_keys > 0) {
        key = &config->ticket_keys[0];
        return 0;
    }
    key = NULL;
    return 0;
}

int s2n_find_ticket_key(struct s2n_config *config, uint8_t name[16], struct s2n_ticket_key *key)
{
    for (int i = 0; i < config->num_prepped_ticket_keys; i++) {
        if (memcmp(config->ticket_keys[i].key_name, name, 16) == 0) {
            key = &config->ticket_keys[i];
            return 0;
        }
    }

    /* Could not find key with that name */
    key = NULL;
    return 0;
}

int print_stuffer(struct s2n_stuffer *state)
{
    uint8_t temp;
    int counter = 0;
    while(s2n_stuffer_data_available(state) > 0) {
        GUARD(s2n_stuffer_read_uint8(state, &temp));
        printf(" %x", temp);
        counter++;
    }
    printf("\n");
    printf("%d\n", counter);
    return 0;
}

int s2n_encrypt_session_ticket(struct s2n_connection *conn, struct s2n_stuffer *to)
{
    struct s2n_ticket_key key;
    struct s2n_session_key aes_ticket_key;
    struct s2n_blob aes_key_blob, aad_blob;

    uint8_t iv_data[S2N_TLS_GCM_IV_LEN] = { 0 };
    struct s2n_blob iv = { .data = iv_data, .size = sizeof(iv_data) };

    uint8_t s_data[S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_EXPLICIT_IV_LEN + S2N_TLS_GCM_TAG_LEN] = { 0 };
    struct s2n_blob state_blob = { .data = s_data, .size = sizeof(s_data) };
    struct s2n_stuffer state;

    uint8_t encrypted_len = S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN;

    /* GUARD(s2n_get_valid_ticket_key(conn->config, key));
     * if (!key) {
     *     // No keys loaded by the user
     *     return -1;
     * }
     */

    /* Initialize the ticket key */
    unsigned char tick_key_name[16] = "2016.07.26\0";
    uint8_t tick_key[S2N_AES256_KEY_LEN] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
            0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
            0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
            0xb3, 0xe5 };
    uint8_t aad_key[S2N_TLS_GCM_AAD_LEN] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

    key.key_name = tick_key_name;
    key.aes_key = tick_key;
    key.aad = aad_key;

    GUARD(s2n_stuffer_write_bytes(to, key.key_name, 16));

    GUARD(s2n_get_public_random_data(&iv));
    GUARD(s2n_stuffer_write(to, &iv));

    s2n_blob_init(&aes_key_blob, key.aes_key, S2N_AES256_KEY_LEN);
    GUARD(s2n_aes256_gcm.init(&aes_ticket_key));
    GUARD(s2n_aes256_gcm.get_encryption_key(&aes_ticket_key, &aes_key_blob));

    s2n_blob_init(&aad_blob, key.aad, S2N_TLS_GCM_AAD_LEN);

    GUARD(s2n_stuffer_init(&state, &state_blob));
    GUARD(s2n_stuffer_skip_write(&state, S2N_TLS_GCM_EXPLICIT_IV_LEN));
    GUARD(s2n_serialize_resumption_state(conn, &state));

    GUARD(s2n_aes256_gcm.io.aead.encrypt(&aes_ticket_key, &iv, &aad_blob, &state_blob, &state_blob));

    state_blob.data = s_data + S2N_TLS_GCM_EXPLICIT_IV_LEN;
    state_blob.size = encrypted_len;

    GUARD(s2n_stuffer_write(to, &state_blob));

    return 0;
}

int s2n_decrypt_session_ticket(struct s2n_connection *conn, struct s2n_stuffer *from)
{
    struct s2n_ticket_key key;
    struct s2n_session_key aes_ticket_key;
    struct s2n_blob aes_key_blob, aad_blob;

    uint8_t key_name[16];

    uint8_t iv_data[S2N_TLS_GCM_IV_LEN] = { 0 };
    struct s2n_blob iv = { .data = iv_data, .size = sizeof(iv_data) };

    uint8_t s_data[S2N_STATE_SIZE_IN_BYTES] = { 0 };
    struct s2n_blob state_blob = { .data = s_data, .size = sizeof(s_data) };
    struct s2n_stuffer state;

    uint8_t en_data[S2N_TLS_GCM_EXPLICIT_IV_LEN + S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN];
    struct s2n_blob en_blob = { .data = en_data, .size = sizeof(en_data) };

    GUARD(s2n_stuffer_read_bytes(from, key_name, 16));

    /* GUARD(s2n_find_ticket_key(conn->config, key_name, key));
     * if (!key) {
     *     // Key no longer valid; do full handshake with NST
     *     conn->session_ticket_status = S2N_EXPECTING_NEW_TICKET;
     *     return 0;
     * }
     */

    /* Initialize the ticket key (same as encryption) */
    unsigned char tick_key_name[16] = "2016.07.26\0";
    uint8_t tick_key[S2N_AES256_KEY_LEN] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
            0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
            0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
            0xb3, 0xe5 };
    uint8_t aad_key[S2N_TLS_GCM_AAD_LEN] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

    key.key_name = tick_key_name;
    key.aes_key = tick_key;
    key.aad = aad_key;

    GUARD(s2n_stuffer_read(from, &iv));

    s2n_blob_init(&aes_key_blob, key.aes_key, S2N_AES256_KEY_LEN);
    GUARD(s2n_aes256_gcm.init(&aes_ticket_key));
    GUARD(s2n_aes256_gcm.get_decryption_key(&aes_ticket_key, &aes_key_blob));

    s2n_blob_init(&aad_blob, key.aad, S2N_TLS_GCM_AAD_LEN);

    GUARD(s2n_stuffer_init(&state, &state_blob));

    GUARD(s2n_stuffer_reread(from));
    GUARD(s2n_stuffer_skip_read(from, 16 + S2N_TLS_GCM_FIXED_IV_LEN));
    GUARD(s2n_stuffer_read(from, &en_blob));

    GUARD(s2n_aes256_gcm.io.aead.decrypt(&aes_ticket_key, &iv, &aad_blob, &en_blob, &en_blob));

    en_blob.data = en_data + S2N_TLS_GCM_EXPLICIT_IV_LEN;
    en_blob.size = S2N_STATE_SIZE_IN_BYTES;
    GUARD(s2n_stuffer_write(&state, &en_blob));

    GUARD(s2n_deserialize_resumption_state(conn, &state));

    /* Check the timestamp from the plaintext state in order to convince
     * yourself of lifetime.
     */

    /*
     * Check expire time from key to see if a new key needs to be assigned to
     * this ticket.
     */

    /* Ticket is decrypted and verified */
    conn->session_ticket_status = S2N_RECEIVED_VALID_TICKET;

    return 0;
}

int s2n_verify_unique_ticket_key(struct s2n_config *config, uint8_t* hash)
{
    /* binary search for the hash; return -1 if found */
    return 0;
}
