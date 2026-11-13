/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define RELAY_CRYPTO_CGO_PRIVATE
#define USE_AES_RAW

#include "orconfig.h"
#include "core/or/or.h"
#include "test/test.h"
#include "lib/cc/compat_compiler.h"
#include "lib/crypt_ops/aes.h"
#include "ext/polyval/polyval.h"
#include "core/crypto/relay_crypto_cgo.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/crypt_ops/crypto_util.h"
#include "core/or/cell_st.h"

#include "test/cgo_vectors.inc"

static const int AESBITS[] = { 128, 192, 256 };

#define ASSERT_CGO_STATE_EQ(a, b) STMT_BEGIN {                         \
    tt_mem_op((a)->nonce, OP_EQ, (b)->nonce, sizeof((a)->nonce));      \
    tt_mem_op((a)->tprime, OP_EQ, (b)->tprime, sizeof((a)->tprime));   \
    tt_mem_op((a)->uiv.uiv_keys_, OP_EQ, (b)->uiv.uiv_keys_,          \
              sizeof((a)->uiv.uiv_keys_));                             \
  } STMT_END

static void
test_crypto_cgo_et_roundtrip(void *arg)
{
  (void)arg;
  uint8_t key[32 + 16]; // max
  uint8_t tweak_h[16];
  uint8_t tweak_x_r[493];
  uint8_t block[16], block_orig[16];
  cgo_et_t et1, et2;
  memset(&et1, 0, sizeof(et1));
  memset(&et2, 0, sizeof(et2));

  et_tweak_t tweak = {
    .uiv = {
      .h = tweak_h,
      .cmd = 7,
    },
    .x_r = tweak_x_r,
  };

  for (int bi = 0; bi < (int) ARRAY_LENGTH(AESBITS); ++bi) {
    const int aesbits = AESBITS[bi];

    for (int i = 0; i < 16; ++i) {
      crypto_rand((char*)key, sizeof(key));
      crypto_rand((char*)tweak_h, sizeof(tweak_h));
      crypto_rand((char*)tweak_x_r, sizeof(tweak_x_r));
      crypto_rand((char*)block_orig, sizeof(block_orig));
      memcpy(block, block_orig, 16);
      cgo_et_init(&et1, aesbits, true, key);
      cgo_et_init(&et2, aesbits, false, key);

      // encrypt-then-decrypt should round-trip.
      cgo_et_encrypt(&et1, tweak, block);
      tt_mem_op(block, OP_NE, block_orig, 16);
      cgo_et_decrypt(&et2, tweak, block);
      tt_mem_op(block, OP_EQ, block_orig, 16);

      // decrypt-then-encrypt should round-trip.
      cgo_et_decrypt(&et2, tweak, block);
      tt_mem_op(block, OP_NE, block_orig, 16);
      cgo_et_encrypt(&et1, tweak, block);
      tt_mem_op(block, OP_EQ, block_orig, 16);

      cgo_et_clear(&et1);
      cgo_et_clear(&et2);
    }
  }
 done:
  cgo_et_clear(&et1);
  cgo_et_clear(&et2);
}

static void
test_crypto_cgo_uiv_roundtrip(void *arg)
{
  (void)arg;
  uint8_t key[64 + 32]; // max
  uint8_t tweak_h[16];
  uint8_t cell[509], cell_orig[509];
  cgo_uiv_t uiv1, uiv2;
  memset(&uiv1, 0, sizeof(uiv1));
  memset(&uiv2, 0, sizeof(uiv2));

  uiv_tweak_t tweak = {
    .h = tweak_h,
    .cmd = 4,
  };

  for (int bi = 0; bi < (int) ARRAY_LENGTH(AESBITS); ++bi) {
    const int aesbits = AESBITS[bi];

    for (int i = 0; i < 16; ++i) {
      crypto_rand((char*)key, sizeof(key));
      crypto_rand((char*)tweak_h, sizeof(tweak_h));
      crypto_rand((char*)cell_orig, sizeof(cell_orig));
      memcpy(cell, cell_orig, sizeof(cell_orig));

      cgo_uiv_init(&uiv1, aesbits, true, key);
      cgo_uiv_init(&uiv2, aesbits, false, key);

      // encrypt-then-decrypt should round-trip.
      cgo_uiv_encrypt(&uiv1, tweak, cell);
      tt_mem_op(cell, OP_NE, cell_orig, sizeof(cell));
      cgo_uiv_decrypt(&uiv2, tweak, cell);
      tt_mem_op(cell, OP_EQ, cell_orig, sizeof(cell));

      // decrypt-then-encrypt should round-trip.
      cgo_uiv_decrypt(&uiv2, tweak, cell);
      tt_mem_op(cell, OP_NE, cell_orig, sizeof(cell));
      cgo_uiv_encrypt(&uiv1, tweak, cell);
      tt_mem_op(cell, OP_EQ, cell_orig, sizeof(cell));

      cgo_uiv_clear(&uiv1);
      cgo_uiv_clear(&uiv2);
    }
  }
 done:
  cgo_uiv_clear(&uiv1);
  cgo_uiv_clear(&uiv2);
}

#define UNHEX(out,inp) STMT_BEGIN {                                     \
    size_t inplen = strlen(inp);                                        \
    tt_int_op(sizeof(out), OP_EQ, inplen / 2);                          \
    int r = base16_decode((char*)(out), sizeof(out), inp, inplen);      \
    tt_int_op(r, OP_EQ, sizeof(out));                                   \
  } STMT_END

#define UNHEX2(out,inp1,inp2) STMT_BEGIN {                              \
    tor_free(unhex_tmp);                                                \
    tor_asprintf(&unhex_tmp, "%s%s", inp1, inp2);                       \
    UNHEX(out, unhex_tmp);                                              \
  } STMT_END

static void
test_crypto_cgo_et_testvec(void *arg)
{
  (void)arg;
  cgo_et_t et;
  memset(&et, 0, sizeof(et));

  for (int i = 0; i < (int)ARRAY_LENGTH(ET_TESTVECS); ++i) {
    const struct et_testvec *tv = &ET_TESTVECS[i];
    uint8_t keys[32];
    uint8_t tweaks[16 + 1 + 493];
    uint8_t block[16], expect[16];
    UNHEX(keys, tv->keys);
    UNHEX(tweaks, tv->tweaks);
    UNHEX(block, tv->block);
    UNHEX(expect, tv->expect);

    et_tweak_t tweak = {
      .uiv = {
        .h = tweaks,
        .cmd = tweaks[16],
      },
      .x_r = tweaks + 17,
    };

    cgo_et_init(&et, 128, tv->encrypt, keys);
    if (tv->encrypt) {
      cgo_et_encrypt(&et, tweak, block);
    } else {
      cgo_et_decrypt(&et, tweak, block);
    }
    cgo_et_clear(&et);

    tt_mem_op(block, OP_EQ, expect, 16);
  }

 done:
  cgo_et_clear(&et);
}

static void
test_crypto_cgo_prf_testvec(void *arg)
{
  (void)arg;
  cgo_prf_t prf;
  memset(&prf, 0, sizeof(prf));

  for (int i = 0; i < (int)ARRAY_LENGTH(PRF_TESTVECS); ++i) {
    const struct prf_testvec *tv = &PRF_TESTVECS[i];
    uint8_t keys[32];
    uint8_t input[16];
    uint8_t expect_t0[493];
    uint8_t expect_t1[80];
    uint8_t output[493]; // max
    UNHEX(keys, tv->keys);
    UNHEX(input, tv->input);

    cgo_prf_init(&prf, 128, keys);
    if (tv->t == 0) {
      UNHEX(expect_t0, tv->expect);
      memset(output, 0, sizeof(output));
      cgo_prf_xor_t0(&prf, input, output);
      tt_mem_op(output, OP_EQ, expect_t0, PRF_T0_DATA_LEN);
    } else {
      tt_int_op(tv->t, OP_EQ, 1);
      UNHEX(expect_t1, tv->expect);
      cgo_prf_gen_t1(&prf, input, output, sizeof(expect_t1));
      tt_mem_op(output, OP_EQ, expect_t1, sizeof(expect_t1));
    }
    cgo_prf_clear(&prf);
  }
 done:
  cgo_prf_clear(&prf);
}

static void
test_crypto_cgo_uiv_testvec(void *arg)
{
  (void)arg;
  cgo_uiv_t uiv;
  memset(&uiv, 0, sizeof(uiv));

  for (int i = 0; i < (int)ARRAY_LENGTH(UIV_TESTVECS); ++i) {
    const struct uiv_testvec *tv = &UIV_TESTVECS[i];
    uint8_t keys[64];
    uint8_t tweaks[17];
    uint8_t x_l[16], x_r[493];
    uint8_t y_l[16], y_r[493];
    uint8_t cell[509];
    UNHEX(keys, tv->keys);
    UNHEX(tweaks, tv->tweaks);
    UNHEX(x_l, tv->x_l);
    UNHEX(x_r, tv->x_r);
    UNHEX(y_l, tv->y.y_l);
    UNHEX(y_r, tv->y.y_r);

    uiv_tweak_t tweak = {
      .h = tweaks,
      .cmd = tweaks[16]
    };
    memcpy(cell, x_l, 16);
    memcpy(cell+16, x_r, 493);

    cgo_uiv_init(&uiv, 128, tv->encrypt, keys);
    if (tv->encrypt) {
      cgo_uiv_encrypt(&uiv, tweak, cell);
    } else {
      cgo_uiv_decrypt(&uiv, tweak, cell);
    }
    cgo_uiv_clear(&uiv);

    tt_mem_op(cell, OP_EQ, y_l, 16);
    tt_mem_op(cell+16, OP_EQ, y_r, 493);
  }

 done:
  cgo_uiv_clear(&uiv);
}

#include "core/crypto/relay_crypto_st.h"

static void
test_crypto_cgo_uiv_update_testvec(void *arg)
{
  (void)arg;
  cgo_uiv_t uiv;
  cgo_uiv_t uiv2;
  memset(&uiv, 0, sizeof(uiv));
  memset(&uiv2, 0, sizeof(uiv2));

  uint8_t tw[16];
  memset(tw, 42, sizeof(tw));
  uiv_tweak_t tweak = {
      .h = tw,
      .cmd = 42
  };

  for (int i = 0; i < (int)ARRAY_LENGTH(UIV_UPDATE_TESTVECS); ++i) {
    const struct uiv_update_testvec *tv = &UIV_UPDATE_TESTVECS[i];
    uint8_t keys[64];
    uint8_t nonce[16];
    uint8_t new_keys[64];
    uint8_t new_nonce[16];
    UNHEX(keys, tv->keys);
    UNHEX(nonce, tv->nonce);
    UNHEX(new_keys, tv->output.new_keys);
    UNHEX(new_nonce, tv->output.new_nonce);

    cgo_uiv_init(&uiv, 128, true, keys);
    cgo_uiv_update(&uiv, 128, true, nonce);
    // Make sure that the recorded keys are what we expect.
    tt_mem_op(uiv.uiv_keys_, OP_EQ, new_keys, 64);
    tt_mem_op(nonce, OP_EQ, new_nonce, 16);

    // Construct a new UIV from these keys and make sure it acts like this one.
    uint8_t cell[509], cell2[509];
    crypto_rand((char*)cell, sizeof(cell));
    memcpy(cell2, cell, 509);
    cgo_uiv_init(&uiv2, 128, true, uiv.uiv_keys_);
    cgo_uiv_encrypt(&uiv, tweak, cell);
    cgo_uiv_encrypt(&uiv2, tweak, cell2);
    tt_mem_op(cell, OP_EQ, cell2, 509);

    cgo_uiv_clear(&uiv);
    cgo_uiv_clear(&uiv2);
  }
 done:
  cgo_uiv_clear(&uiv);
  cgo_uiv_clear(&uiv2);
}

static void
test_crypto_cgo_fwd(void *arg)
{
  (void)arg;

  #define N_HOPS 3
  uint8_t key_material[N_HOPS][112]; // max.
  cgo_crypt_t *client[N_HOPS];
  cgo_crypt_t *relays[N_HOPS];

  memset(client, 0, sizeof(client));
  memset(relays, 0, sizeof(relays));

  for (int bi = 0; bi < (int) ARRAY_LENGTH(AESBITS); ++bi) {
    const int aesbits = AESBITS[bi];

    size_t klen = cgo_key_material_len(aesbits);
    tt_uint_op(klen, OP_LE, sizeof(key_material[0]));
    crypto_rand((char*)&key_material, sizeof(key_material));
    for (int i = 0; i < N_HOPS; ++i) {
      client[i] = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                                aesbits, key_material[i], klen);
      relays[i] = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                                aesbits, key_material[i], klen);
    }
    for (int trial = 0; trial < 64; ++trial) {
      int target_hop = crypto_rand_int(3);
      cell_t cell, cell_orig;
      uint8_t tag_client[SENDME_TAG_LEN_CGO];
      const uint8_t *tagp = NULL;

      memset(&cell, 0, sizeof(cell));
      if (crypto_rand_int(2) == 0) {
        cell.command = CELL_RELAY;
      } else {
        cell.command = CELL_RELAY_EARLY;
      }
      crypto_rand((char*) cell.payload+SENDME_TAG_LEN_CGO,
                  sizeof(cell.payload)-SENDME_TAG_LEN_CGO);
      memcpy(&cell_orig, &cell, sizeof(cell));

      // First the client encrypts the cell...
      cgo_crypt_client_originate(client[target_hop], &cell, &tagp);
      tt_assert(tagp);
      memcpy(tag_client, tagp, SENDME_TAG_LEN_CGO);
      for (int i = target_hop - 1; i >= 0; --i) {
        cgo_crypt_client_forward(client[i], &cell);
      }

      // Now the relays handle the cell...
      bool cell_recognized = false;
      for (int i = 0; i < N_HOPS; ++i) {
        tagp = NULL;
        cgo_crypt_relay_forward(relays[i], &cell, &tagp);
        if (tagp) {
          tt_int_op(i, OP_EQ, target_hop);
          tt_mem_op(tagp, OP_EQ, tag_client, SENDME_TAG_LEN_CGO);
          cell_recognized = true;
          break;
        }
      }
      tt_assert(cell_recognized);
      tt_int_op(cell.command, OP_EQ, cell_orig.command);
      tt_mem_op(cell.payload + SENDME_TAG_LEN_CGO, OP_EQ,
                cell_orig.payload + SENDME_TAG_LEN_CGO,
                sizeof(cell.payload) - SENDME_TAG_LEN_CGO);
    }
    for (int i = 0; i < N_HOPS; ++i) {
      cgo_crypt_free(client[i]);
      cgo_crypt_free(relays[i]);
    }
  }

 done:
  for (int i = 0; i < N_HOPS; ++i) {
    cgo_crypt_free(client[i]);
    cgo_crypt_free(relays[i]);
  }
#undef N_HOPS
}

static void
test_crypto_cgo_rev(void *arg)
{
  (void)arg;

  #define N_HOPS 3
  uint8_t key_material[N_HOPS][112]; // max.
  cgo_crypt_t *client[N_HOPS];
  cgo_crypt_t *relays[N_HOPS];

  memset(client, 0, sizeof(client));
  memset(relays, 0, sizeof(relays));

  for (int bi = 0; bi < (int) ARRAY_LENGTH(AESBITS); ++bi) {
    const int aesbits = AESBITS[bi];

    size_t klen = cgo_key_material_len(aesbits);
    tt_uint_op(klen, OP_LE, sizeof(key_material[0]));
    crypto_rand((char*)&key_material, sizeof(key_material));
    for (int i = 0; i < N_HOPS; ++i) {
      client[i] = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                                 aesbits, key_material[i], klen);
      relays[i] = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                                aesbits, key_material[i], klen);
    }
    for (int trial = 0; trial < 64; ++trial) {
      int origin_hop = crypto_rand_int(3);
      cell_t cell, cell_orig;
      uint8_t tag_relay[SENDME_TAG_LEN_CGO];
      const uint8_t *tagp = NULL;

      memset(&cell, 0, sizeof(cell));
      cell.command = CELL_RELAY;
      crypto_rand((char*) cell.payload+SENDME_TAG_LEN_CGO,
                  sizeof(cell.payload)-SENDME_TAG_LEN_CGO);
      memcpy(&cell_orig, &cell, sizeof(cell));

      // First the specified relay encrypts the cell...
      cgo_crypt_relay_originate(relays[origin_hop], &cell, &tagp);
      tt_assert(tagp);
      memcpy(tag_relay, tagp, SENDME_TAG_LEN_CGO);
      for (int i = origin_hop - 1; i >= 0; --i) {
        cgo_crypt_relay_backward(relays[i], &cell);
      }

      // Now the client handles the cell.
      bool cell_recognized = false;
      for (int i = 0; i < N_HOPS; ++i) {
        tagp = NULL;
        cgo_crypt_client_backward(client[i], &cell, &tagp);
        if (tagp) {
          tt_int_op(i, OP_EQ, origin_hop);
          tt_mem_op(tagp, OP_EQ, tag_relay, SENDME_TAG_LEN_CGO);
          cell_recognized = true;
          break;
        }
      }
      tt_assert(cell_recognized);
      tt_int_op(cell.command, OP_EQ, cell_orig.command);
      tt_mem_op(cell.payload + SENDME_TAG_LEN_CGO, OP_EQ,
                cell_orig.payload + SENDME_TAG_LEN_CGO,
                sizeof(cell.payload) - SENDME_TAG_LEN_CGO);
    }
    for (int i = 0; i < N_HOPS; ++i) {
      cgo_crypt_free(client[i]);
      cgo_crypt_free(relays[i]);
    }
  }

 done:
  for (int i = 0; i < N_HOPS; ++i) {
    cgo_crypt_free(client[i]);
    cgo_crypt_free(relays[i]);
  }
#undef N_HOPS
}

/** Verify the two-ended state invariant over a long forward sequence. */
static void
test_crypto_cgo_state_sync_fwd(void *arg)
{
  (void)arg;
  #define N_HOPS 3
  const int aesbits = 128;
  const size_t klen = cgo_key_material_len(aesbits);
  uint8_t keys[N_HOPS][80];
  cgo_crypt_t *client[N_HOPS] = { NULL, NULL, NULL };
  cgo_crypt_t *relay[N_HOPS] = { NULL, NULL, NULL };

  for (int h = 0; h < N_HOPS; ++h) {
    for (size_t i = 0; i < klen; ++i)
      keys[h][i] = (uint8_t)(i * 17 + h * 53 + 11);
    client[h] = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                              aesbits, keys[h], klen);
    relay[h] = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                             aesbits, keys[h], klen);
  }

  for (int trial = 0; trial < 1024; ++trial) {
    const int target = trial % N_HOPS;
    cell_t cell;
    memset(&cell, 0, sizeof(cell));
    cell.command = (trial & 1) ? CELL_RELAY : CELL_RELAY_EARLY;
    for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
      cell.payload[i] = (uint8_t)(trial + i * 29);

    const uint8_t *tag = NULL;
    cgo_crypt_client_originate(client[target], &cell, &tag);
    tt_assert(tag);
    for (int h = target - 1; h >= 0; --h)
      cgo_crypt_client_forward(client[h], &cell);

    bool recognized = false;
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_relay_forward(relay[h], &cell, &tag);
      if (tag) {
        tt_int_op(h, OP_EQ, target);
        recognized = true;
        break;
      }
    }
    tt_assert(recognized);
    for (int h = 0; h < N_HOPS; ++h)
      ASSERT_CGO_STATE_EQ(client[h], relay[h]);
  }

 done:
  for (int h = 0; h < N_HOPS; ++h) {
    cgo_crypt_free(client[h]);
    cgo_crypt_free(relay[h]);
  }
  #undef N_HOPS
}

/** Verify the two-ended state invariant over a long backward sequence. */
static void
test_crypto_cgo_state_sync_rev(void *arg)
{
  (void)arg;
  #define N_HOPS 3
  const int aesbits = 128;
  const size_t klen = cgo_key_material_len(aesbits);
  uint8_t keys[N_HOPS][80];
  cgo_crypt_t *client[N_HOPS] = { NULL, NULL, NULL };
  cgo_crypt_t *relay[N_HOPS] = { NULL, NULL, NULL };

  for (int h = 0; h < N_HOPS; ++h) {
    for (size_t i = 0; i < klen; ++i)
      keys[h][i] = (uint8_t)(i * 31 + h * 47 + 7);
    client[h] = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                              aesbits, keys[h], klen);
    relay[h] = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                             aesbits, keys[h], klen);
  }

  for (int trial = 0; trial < 1024; ++trial) {
    const int origin = trial % N_HOPS;
    cell_t cell;
    memset(&cell, 0, sizeof(cell));
    cell.command = (trial & 1) ? CELL_RELAY : CELL_RELAY_EARLY;
    for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
      cell.payload[i] = (uint8_t)(trial * 3 + i * 13);

    const uint8_t *tag = NULL;
    cgo_crypt_relay_originate(relay[origin], &cell, &tag);
    tt_assert(tag);
    for (int h = origin - 1; h >= 0; --h)
      cgo_crypt_relay_backward(relay[h], &cell);

    bool recognized = false;
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_client_backward(client[h], &cell, &tag);
      if (tag) {
        tt_int_op(h, OP_EQ, origin);
        recognized = true;
        break;
      }
    }
    tt_assert(recognized);
    for (int h = 0; h < N_HOPS; ++h)
      ASSERT_CGO_STATE_EQ(client[h], relay[h]);
  }

 done:
  for (int h = 0; h < N_HOPS; ++h) {
    cgo_crypt_free(client[h]);
    cgo_crypt_free(relay[h]);
  }
  #undef N_HOPS
}

/**
 * Flip every payload bit in a valid forward cell.  No modified cell may be
 * recognized, and the next valid cell must not repair the desynchronized
 * receiver state.
 */
static void
test_crypto_cgo_tamper_fwd(void *arg)
{
  (void)arg;
  #define N_HOPS 3
  const int aesbits = 128;
  const size_t klen = cgo_key_material_len(aesbits);
  uint8_t keys[N_HOPS][80];
  cgo_crypt_t *client[N_HOPS] = { NULL, NULL, NULL };
  cgo_crypt_t *relay[N_HOPS] = { NULL, NULL, NULL };

  for (int h = 0; h < N_HOPS; ++h)
    for (size_t i = 0; i < klen; ++i)
      keys[h][i] = (uint8_t)(i * 19 + h * 59 + 5);

  for (size_t bit = 0; bit < CELL_PAYLOAD_SIZE * 8; ++bit) {
    for (int h = 0; h < N_HOPS; ++h) {
      client[h] = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                                aesbits, keys[h], klen);
      relay[h] = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                               aesbits, keys[h], klen);
    }

    cell_t cell;
    memset(&cell, 0, sizeof(cell));
    cell.command = CELL_RELAY;
    for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
      cell.payload[i] = (uint8_t)(i * 23 + bit);

    const int target = 2;
    const uint8_t *tag = NULL;
    cgo_crypt_client_originate(client[target], &cell, &tag);
    for (int h = target - 1; h >= 0; --h)
      cgo_crypt_client_forward(client[h], &cell);
    cell.payload[bit / 8] ^= (uint8_t)(1u << (bit & 7));

    bool recognized = false;
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_relay_forward(relay[h], &cell, &tag);
      recognized |= tag != NULL;
    }
    tt_assert(!recognized);

    memset(&cell, 0, sizeof(cell));
    cell.command = CELL_RELAY;
    cgo_crypt_client_originate(client[target], &cell, &tag);
    for (int h = target - 1; h >= 0; --h)
      cgo_crypt_client_forward(client[h], &cell);
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_relay_forward(relay[h], &cell, &tag);
      recognized |= tag != NULL;
    }
    tt_assert(!recognized);

    for (int h = 0; h < N_HOPS; ++h) {
      cgo_crypt_free(client[h]);
      cgo_crypt_free(relay[h]);
    }
  }

 done:
  for (int h = 0; h < N_HOPS; ++h) {
    cgo_crypt_free(client[h]);
    cgo_crypt_free(relay[h]);
  }
  #undef N_HOPS
}

/** Mirror the exhaustive bit-flip experiment for cells travelling to the
 * client. */
static void
test_crypto_cgo_tamper_rev(void *arg)
{
  (void)arg;
  #define N_HOPS 3
  const int aesbits = 128;
  const size_t klen = cgo_key_material_len(aesbits);
  uint8_t keys[N_HOPS][80];
  cgo_crypt_t *client[N_HOPS] = { NULL, NULL, NULL };
  cgo_crypt_t *relay[N_HOPS] = { NULL, NULL, NULL };

  for (int h = 0; h < N_HOPS; ++h)
    for (size_t i = 0; i < klen; ++i)
      keys[h][i] = (uint8_t)(i * 43 + h * 61 + 3);

  for (size_t bit = 0; bit < CELL_PAYLOAD_SIZE * 8; ++bit) {
    for (int h = 0; h < N_HOPS; ++h) {
      client[h] = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                                aesbits, keys[h], klen);
      relay[h] = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                               aesbits, keys[h], klen);
    }

    cell_t cell;
    memset(&cell, 0, sizeof(cell));
    cell.command = CELL_RELAY;
    for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
      cell.payload[i] = (uint8_t)(i * 37 + bit);

    const int origin = 2;
    const uint8_t *tag = NULL;
    cgo_crypt_relay_originate(relay[origin], &cell, &tag);
    for (int h = origin - 1; h >= 0; --h)
      cgo_crypt_relay_backward(relay[h], &cell);
    cell.payload[bit / 8] ^= (uint8_t)(1u << (bit & 7));

    bool recognized = false;
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_client_backward(client[h], &cell, &tag);
      recognized |= tag != NULL;
    }
    tt_assert(!recognized);

    memset(&cell, 0, sizeof(cell));
    cell.command = CELL_RELAY;
    cgo_crypt_relay_originate(relay[origin], &cell, &tag);
    for (int h = origin - 1; h >= 0; --h)
      cgo_crypt_relay_backward(relay[h], &cell);
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_client_backward(client[h], &cell, &tag);
      recognized |= tag != NULL;
    }
    tt_assert(!recognized);

    for (int h = 0; h < N_HOPS; ++h) {
      cgo_crypt_free(client[h]);
      cgo_crypt_free(relay[h]);
    }
  }

 done:
  for (int h = 0; h < N_HOPS; ++h) {
    cgo_crypt_free(client[h]);
    cgo_crypt_free(relay[h]);
  }
  #undef N_HOPS
}

/** The channel command is associated data.  Mutating only that command must
 * be detected in both directions. */
static void
test_crypto_cgo_tamper_command(void *arg)
{
  (void)arg;
  const int aesbits = 128;
  const size_t klen = cgo_key_material_len(aesbits);
  uint8_t keys[80];
  for (size_t i = 0; i < klen; ++i)
    keys[i] = (uint8_t)(i * 71 + 9);

  cgo_crypt_t *client_fwd = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                                           aesbits, keys, klen);
  cgo_crypt_t *relay_fwd = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                                          aesbits, keys, klen);
  cgo_crypt_t *client_rev = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                                           aesbits, keys, klen);
  cgo_crypt_t *relay_rev = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                                          aesbits, keys, klen);
  cell_t cell;
  const uint8_t *tag = NULL;

  memset(&cell, 0x5a, sizeof(cell));
  cell.command = CELL_RELAY;
  cgo_crypt_client_originate(client_fwd, &cell, &tag);
  cell.command = CELL_RELAY_EARLY;
  tag = NULL;
  cgo_crypt_relay_forward(relay_fwd, &cell, &tag);
  tt_assert(tag == NULL);

  memset(&cell, 0xa5, sizeof(cell));
  cell.command = CELL_RELAY;
  cgo_crypt_relay_originate(relay_rev, &cell, &tag);
  cell.command = CELL_RELAY_EARLY;
  tag = NULL;
  cgo_crypt_client_backward(client_rev, &cell, &tag);
  tt_assert(tag == NULL);

 done:
  cgo_crypt_free(client_fwd);
  cgo_crypt_free(relay_fwd);
  cgo_crypt_free(client_rev);
  cgo_crypt_free(relay_rev);
}

/**
 * Exercise the state machine with whole-cell replay, loss, and reordering.
 * TCP prevents these conditions accidentally, but an active relay can create
 * them.  None of the replayed or reordered cells may be accepted.  A replay
 * of the most recent backward cell is state-idempotent at the primitive layer;
 * the Tor caller still closes the circuit when no hop recognizes that replay.
 * Run the same checks for every AES key size supported by the primitive.
 */
static void
test_crypto_cgo_sequence_faults(void *arg)
{
  (void)arg;
  uint8_t keys[112];

  for (size_t ai = 0; ai < ARRAY_LENGTH(AESBITS); ++ai) {
    const int aesbits = AESBITS[ai];
    const size_t klen = cgo_key_material_len(aesbits);
    for (size_t i = 0; i < klen; ++i)
      keys[i] = (uint8_t)(i * 37 + aesbits + 19);

    /* Forward replay, followed by a fresh cell. */
    {
      cgo_crypt_t *client = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                                           aesbits, keys, klen);
      cgo_crypt_t *relay = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                                          aesbits, keys, klen);
      cell_t cell;
      cell_t replay;
      const uint8_t *tag = NULL;
      memset(&cell, 0x31, sizeof(cell));
      cell.command = CELL_RELAY;
      cgo_crypt_client_originate(client, &cell, &tag);
      memcpy(&replay, &cell, sizeof(replay));
      tag = NULL;
      cgo_crypt_relay_forward(relay, &cell, &tag);
      tt_assert(tag);
      tag = NULL;
      cgo_crypt_relay_forward(relay, &replay, &tag);
      tt_assert(!tag);
      memset(&cell, 0x32, sizeof(cell));
      cell.command = CELL_RELAY;
      cgo_crypt_client_originate(client, &cell, &tag);
      tag = NULL;
      cgo_crypt_relay_forward(relay, &cell, &tag);
      tt_assert(!tag);
      cgo_crypt_free(client);
      cgo_crypt_free(relay);
    }

    /* Forward loss and reordering. */
    {
      cgo_crypt_t *client = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                                           aesbits, keys, klen);
      cgo_crypt_t *relay = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                                          aesbits, keys, klen);
      cell_t first;
      cell_t second;
      const uint8_t *tag = NULL;
      memset(&first, 0x41, sizeof(first));
      first.command = CELL_RELAY;
      cgo_crypt_client_originate(client, &first, &tag);
      memset(&second, 0x42, sizeof(second));
      second.command = CELL_RELAY_EARLY;
      cgo_crypt_client_originate(client, &second, &tag);
      tag = NULL;
      cgo_crypt_relay_forward(relay, &second, &tag);
      tt_assert(!tag);
      tag = NULL;
      cgo_crypt_relay_forward(relay, &first, &tag);
      tt_assert(!tag);
      cgo_crypt_free(client);
      cgo_crypt_free(relay);
    }

    /* Backward replay, followed by a fresh cell. */
    {
      cgo_crypt_t *client = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                                           aesbits, keys, klen);
      cgo_crypt_t *relay = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                                          aesbits, keys, klen);
      cell_t cell;
      cell_t replay;
      const uint8_t *tag = NULL;
      memset(&cell, 0x51, sizeof(cell));
      cell.command = CELL_RELAY;
      cgo_crypt_relay_originate(relay, &cell, &tag);
      memcpy(&replay, &cell, sizeof(replay));
      tag = NULL;
      cgo_crypt_client_backward(client, &cell, &tag);
      tt_assert(tag);
      tag = NULL;
      cgo_crypt_client_backward(client, &replay, &tag);
      tt_assert(!tag);
      memset(&cell, 0x52, sizeof(cell));
      cell.command = CELL_RELAY;
      cgo_crypt_relay_originate(relay, &cell, &tag);
      tag = NULL;
      cgo_crypt_client_backward(client, &cell, &tag);
      tt_assert(tag);
      ASSERT_CGO_STATE_EQ(client, relay);
      cgo_crypt_free(client);
      cgo_crypt_free(relay);
    }

    /* Backward loss and reordering. */
    {
      cgo_crypt_t *client = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                                           aesbits, keys, klen);
      cgo_crypt_t *relay = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                                          aesbits, keys, klen);
      cell_t first;
      cell_t second;
      const uint8_t *tag = NULL;
      memset(&first, 0x61, sizeof(first));
      first.command = CELL_RELAY;
      cgo_crypt_relay_originate(relay, &first, &tag);
      memset(&second, 0x62, sizeof(second));
      second.command = CELL_RELAY_EARLY;
      cgo_crypt_relay_originate(relay, &second, &tag);
      tag = NULL;
      cgo_crypt_client_backward(client, &second, &tag);
      tt_assert(!tag);
      tag = NULL;
      cgo_crypt_client_backward(client, &first, &tag);
      tt_assert(!tag);
      cgo_crypt_free(client);
      cgo_crypt_free(relay);
    }
  }

 done:
  memwipe(keys, 0, sizeof(keys));
}

/* Reproduce the backward-direction IPR+ resynchronization distinguisher
 * described by Pillwax (2026), Section 3.5.4, at one intermediate CGO
 * layer.  This is a primitive-level property: real Tor closes the circuit
 * after the first unrecognized inbound cell, so this test does not claim a
 * deployable network attack. */
static void
test_crypto_cgo_backward_ipr_resync(void *arg)
{
  (void)arg;
  const int aesbits = 128;
  const size_t keylen = cgo_key_material_len(aesbits);
  uint8_t key_material[80];
  cgo_crypt_t *client = NULL;
  cgo_crypt_t *relay = NULL;
  cell_t first_input, first_output, injected;
  cell_t second_input, second_plaintext;
  const uint8_t *recognized = NULL;

  tt_uint_op(keylen, OP_EQ, sizeof(key_material));
  for (size_t i = 0; i < sizeof(key_material); ++i)
    key_material[i] = (uint8_t)(i * 13 + 7);

  client = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                         aesbits, key_material, keylen);
  relay = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                        aesbits, key_material, keylen);
  tt_assert(client);
  tt_assert(relay);

  /* The intermediate relay processes a first deeper-layer ciphertext c0,
   * producing c1 and advancing only its chaining tag to T1. */
  memset(&first_input, 0, sizeof(first_input));
  first_input.command = CELL_RELAY;
  for (size_t i = 0; i < sizeof(first_input.payload); ++i)
    first_input.payload[i] = (uint8_t)(i * 29 + 3);
  first_output = first_input;
  cgo_crypt_relay_backward(relay, &first_output);

  /* Replace the right side of c1 while preserving its left tag T1.  Client
   * decryption does not recognize this cell, but it sets its chaining tag
   * to T1, making the client and relay layer states equal again. */
  injected = first_output;
  injected.payload[SENDME_TAG_LEN_CGO + 11] ^= 0x80;
  cgo_crypt_client_backward(client, &injected, &recognized);
  tt_ptr_op(recognized, OP_EQ, NULL);
  tt_mem_op(client->tprime, OP_EQ, relay->tprime,
            SENDME_TAG_LEN_CGO);
  ASSERT_CGO_STATE_EQ(client, relay);

  /* With equal state and tweak, the next honest relay transformation is
   * inverted exactly by the client, which is the probability-one real/ideal
   * distinguisher in the IPR+ experiment. */
  memset(&second_input, 0, sizeof(second_input));
  second_input.command = CELL_RELAY;
  for (size_t i = 0; i < sizeof(second_input.payload); ++i)
    second_input.payload[i] = (uint8_t)(i * 17 + 0x42);
  second_plaintext = second_input;
  cgo_crypt_relay_backward(relay, &second_input);
  recognized = NULL;
  cgo_crypt_client_backward(client, &second_input, &recognized);
  tt_ptr_op(recognized, OP_EQ, NULL);
  tt_mem_op(second_input.payload, OP_EQ, second_plaintext.payload,
            sizeof(second_input.payload));
  ASSERT_CGO_STATE_EQ(client, relay);

 done:
  cgo_crypt_free(client);
  cgo_crypt_free(relay);
}

/* Show why the single-layer IPR+ distinguisher does not directly become a
 * three-hop Tor decryption attack.  The client processes every layer before
 * rejecting the injected cell: the outer layer resynchronizes, but inner
 * layers do not, and the next honest cell is still unrecognized. */
static void
test_crypto_cgo_backward_ipr_multihop_containment(void *arg)
{
  (void)arg;
  #define N_HOPS 3
  const int aesbits = 128;
  const size_t keylen = cgo_key_material_len(aesbits);
  uint8_t keys[N_HOPS][80];
  cgo_crypt_t *client[N_HOPS] = { NULL, NULL, NULL };
  cgo_crypt_t *relay[N_HOPS] = { NULL, NULL, NULL };
  cell_t cell;
  const uint8_t *tag = NULL;

  for (int hop = 0; hop < N_HOPS; ++hop) {
    for (size_t i = 0; i < keylen; ++i)
      keys[hop][i] = (uint8_t)(i * 23 + hop * 67 + 5);
    client[hop] = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                                aesbits, keys[hop], keylen);
    relay[hop] = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                               aesbits, keys[hop], keylen);
    tt_assert(client[hop]);
    tt_assert(relay[hop]);
  }

  /* Build a legitimate three-layer cell from the exit, then let the
   * client-facing entry preserve its left tag while changing the body. */
  memset(&cell, 0, sizeof(cell));
  cell.command = CELL_RELAY;
  for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
    cell.payload[i] = (uint8_t)(i * 31 + 9);
  cgo_crypt_relay_originate(relay[2], &cell, &tag);
  tt_assert(tag);
  cgo_crypt_relay_backward(relay[1], &cell);
  cgo_crypt_relay_backward(relay[0], &cell);
  cell.payload[SENDME_TAG_LEN_CGO + 11] ^= 0x80;

  bool recognized = false;
  for (int hop = 0; hop < N_HOPS; ++hop) {
    tag = NULL;
    cgo_crypt_client_backward(client[hop], &cell, &tag);
    recognized |= tag != NULL;
  }
  tt_assert(!recognized);

  /* The attacked outer layer has the single-layer resynchronization
   * property, but the next two layers no longer share the same chaining
   * state with their relay counterparts. */
  ASSERT_CGO_STATE_EQ(client[0], relay[0]);
  tt_mem_op(client[1]->tprime, OP_NE, relay[1]->tprime,
            SENDME_TAG_LEN_CGO);
  tt_mem_op(client[2]->tprime, OP_NE, relay[2]->tprime,
            SENDME_TAG_LEN_CGO);

  /* Even if an implementation incorrectly kept the circuit open, a second
   * legitimate exit cell is not recognized end to end. */
  memset(&cell, 0, sizeof(cell));
  cell.command = CELL_RELAY;
  for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
    cell.payload[i] = (uint8_t)(i * 19 + 0x51);
  tag = NULL;
  cgo_crypt_relay_originate(relay[2], &cell, &tag);
  tt_assert(tag);
  cgo_crypt_relay_backward(relay[1], &cell);
  cgo_crypt_relay_backward(relay[0], &cell);
  recognized = false;
  for (int hop = 0; hop < N_HOPS; ++hop) {
    tag = NULL;
    cgo_crypt_client_backward(client[hop], &cell, &tag);
    recognized |= tag != NULL;
  }
  tt_assert(!recognized);

 done:
  for (int hop = 0; hop < N_HOPS; ++hop) {
    cgo_crypt_free(client[hop]);
    cgo_crypt_free(relay[hop]);
  }
  #undef N_HOPS
}

static void
test_crypto_cgo_relay_testvec(void *arg)
{
  (void)arg;
  char *unhex_tmp = NULL;
  cgo_crypt_t *cgo = NULL;
  for (int i = 0; i < (int)ARRAY_LENGTH(CGO_RELAY_TESTVECS); ++i) {
    const struct cgo_relay_testvec *tv = &CGO_RELAY_TESTVECS[i];
    const int aesbits = 128;
    uint8_t keys[80], expect_keys[80], expect_tprime[SENDME_TAG_LEN_CGO],
      cmd[1];
    cell_t cell;
    cell_t expect_cell;
    tt_int_op(sizeof(keys), OP_EQ, cgo_key_material_len(aesbits));
    UNHEX2(keys, tv->state_in.keys, tv->state_in.nonce);
    cgo_mode_t mode =
      tv->inbound ? CGO_MODE_RELAY_BACKWARD : CGO_MODE_RELAY_FORWARD;
    cgo = cgo_crypt_new(mode, aesbits, keys, sizeof(keys));
    tt_assert(cgo);
    UNHEX(cgo->tprime, tv->state_in.tprime);
    memset(&cell, 0, sizeof(cell));
    UNHEX(cmd, tv->cmd);
    cell.command = cmd[0];
    UNHEX2(cell.payload, tv->tag, tv->msg);

    memset(&expect_cell, 0, sizeof(expect_cell));
    expect_cell.command = cell.command;
    UNHEX2(expect_cell.payload,
           tv->output.result.t_out, tv->output.result.msg_out);
    UNHEX2(expect_keys,
           tv->output.state.keys, tv->output.state.nonce);
    UNHEX(expect_tprime, tv->output.state.tprime);

    if (tv->inbound) {
      cgo_crypt_relay_backward(cgo, &cell);
    } else {
      const uint8_t *tagp = NULL;
      cgo_crypt_relay_forward(cgo, &cell, &tagp);
      tt_ptr_op(tagp, OP_EQ, NULL);
    }

    tt_mem_op(cell.payload, OP_EQ, expect_cell.payload, sizeof(cell.payload));
    tt_mem_op(cgo->uiv.uiv_keys_, OP_EQ, expect_keys, 64);
    tt_mem_op(cgo->nonce, OP_EQ, expect_keys + 64, 16);
    tt_mem_op(cgo->tprime, OP_EQ, expect_tprime, 16);

    cgo_crypt_free(cgo);
  }
 done:
  tor_free(unhex_tmp);
  cgo_crypt_free(cgo);
}

static void
test_crypto_cgo_relay_originate_testvec(void *arg)
{
  (void)arg;
  char *unhex_tmp = NULL;
  cgo_crypt_t *cgo = NULL;
  for (int i = 0; i < (int)ARRAY_LENGTH(CGO_RELAY_ORIGINATE_TESTVECS); ++i) {
    const struct cgo_relay_originate_testvec *tv =
      &CGO_RELAY_ORIGINATE_TESTVECS[i];
    const int aesbits = 128;
    uint8_t keys[80], expect_keys[80], expect_tprime[SENDME_TAG_LEN_CGO],
      cmd[1];
    cell_t cell;
    cell_t expect_cell;
    tt_int_op(sizeof(keys), OP_EQ, cgo_key_material_len(aesbits));
    UNHEX2(keys, tv->state_in.keys, tv->state_in.nonce);
    cgo = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD, aesbits, keys, sizeof(keys));
    tt_assert(cgo);
    UNHEX(cgo->tprime, tv->state_in.tprime);
    memset(&cell, 0, sizeof(cell));
    UNHEX(cmd, tv->cmd);
    cell.command = cmd[0];
    UNHEX2(cell.payload, "00000000000000000000000000000000", tv->msg);

    memset(&expect_cell, 0, sizeof(expect_cell));
    expect_cell.command = cell.command;
    UNHEX2(expect_cell.payload,
           tv->output.result.t_out, tv->output.result.msg_out);
    UNHEX2(expect_keys,
           tv->output.state.keys, tv->output.state.nonce);
    UNHEX(expect_tprime, tv->output.state.tprime);

    const uint8_t *tagp = NULL;
    cgo_crypt_relay_originate(cgo, &cell, &tagp);
    tt_ptr_op(tagp, OP_NE, NULL);

    tt_mem_op(cell.payload, OP_EQ, expect_cell.payload, sizeof(cell.payload));
    tt_mem_op(cgo->uiv.uiv_keys_, OP_EQ, expect_keys, 64);
    tt_mem_op(cgo->nonce, OP_EQ, expect_keys + 64, 16);
    tt_mem_op(cgo->tprime, OP_EQ, expect_tprime, 16);

    cgo_crypt_free(cgo);
  }
 done:
  tor_free(unhex_tmp);
  cgo_crypt_free(cgo);
}

static void
test_crypto_cgo_client_originate_testvec(void *arg)
{
  (void) arg;
  char *unhex_tmp = NULL;
  cgo_crypt_t *cgo[3] = { NULL, NULL, NULL };
  for (int tv_i = 0; tv_i < (int)ARRAY_LENGTH(CGO_CLIENT_ORIGINATE_TESTVECS);
       ++tv_i) {
    const struct cgo_client_originate_testvec *tv =
      &CGO_CLIENT_ORIGINATE_TESTVECS[tv_i];
    const int aesbits = 128;
    uint8_t keys[80], expect_keys[80], expect_tprime[SENDME_TAG_LEN_CGO],
      cmd[1];
    cell_t cell;
    cell_t expect_cell;
    for (int i = 0; i < 3; ++i) {
      tt_int_op(sizeof(keys), OP_EQ, cgo_key_material_len(aesbits));
      UNHEX2(keys, tv->state_in[i].keys, tv->state_in[i].nonce);
      cgo[i] = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                             aesbits, keys, sizeof(keys));
      tt_assert(cgo[i]);
      UNHEX(cgo[i]->tprime, tv->state_in[i].tprime);
    }

    memset(&cell, 0, sizeof(cell));
    UNHEX(cmd, tv->cmd);
    cell.command = cmd[0];
    UNHEX2(cell.payload, "00000000000000000000000000000000", tv->msg);

    memset(&expect_cell, 0, sizeof(expect_cell));
    expect_cell.command = cell.command;
    UNHEX2(expect_cell.payload,
           tv->output.result.t_out, tv->output.result.msg_out);

    tt_int_op(tv->target_hop, OP_GE, 1); // Hop is 0-indexed.
    int target_hop = tv->target_hop - 1;
    const uint8_t *tagp = NULL;
    cgo_crypt_client_originate(cgo[target_hop], &cell, &tagp);
    tt_ptr_op(tagp, OP_NE, NULL);
    for (int i = target_hop - 1; i >= 0; --i) {
      cgo_crypt_client_forward(cgo[i], &cell);
    }
    tt_mem_op(cell.payload, OP_EQ, expect_cell.payload, sizeof(cell.payload));

    for (int i = 0; i < 3; ++i) {
      UNHEX2(expect_keys,
             tv->output.state[i].keys, tv->output.state[i].nonce);
      UNHEX(expect_tprime, tv->output.state[i].tprime);

      tt_mem_op(cgo[i]->uiv.uiv_keys_, OP_EQ, expect_keys, 64);
      tt_mem_op(cgo[i]->nonce, OP_EQ, expect_keys + 64, 16);
      tt_mem_op(cgo[i]->tprime, OP_EQ, expect_tprime, 16);
    }

    for (int i = 0; i < 3; ++i)
      cgo_crypt_free(cgo[i]);
  }
 done:
  tor_free(unhex_tmp);
  for (int i = 0; i < 3; ++i)
    cgo_crypt_free(cgo[i]);
}

/** Write bytes as lowercase hexadecimal for the cross-implementation trace. */
static void
cgo_trace_hex(FILE *f, const uint8_t *bytes, size_t n)
{
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < n; ++i) {
    fputc(hex[bytes[i] >> 4], f);
    fputc(hex[bytes[i] & 15], f);
  }
}

/** Write the externally comparable portion of one CGO direction state. */
static void
cgo_trace_state(FILE *f, const char *label, const cgo_crypt_t *cgo)
{
  fprintf(f, " %s=", label);
  cgo_trace_hex(f, cgo->uiv.uiv_keys_, 64);
  fputc(':', f);
  cgo_trace_hex(f, cgo->nonce, sizeof(cgo->nonce));
  fputc(':', f);
  cgo_trace_hex(f, cgo->tprime, sizeof(cgo->tprime));
}

/**
 * Emit a deterministic, multi-operation transcript for differential testing
 * against Arti.  The trace contains the wire cell and every hop's post-cell
 * state; no random generator or shared expected-output vector is involved.
 */
static void
test_crypto_cgo_cross_impl_trace(void *arg)
{
  (void)arg;
  #define N_HOPS 3
  const char *path = getenv("CGO_DIFF_TRACE_PATH");
  FILE *f = NULL;
  cgo_crypt_t *client[N_HOPS] = { NULL, NULL, NULL };
  cgo_crypt_t *relay[N_HOPS] = { NULL, NULL, NULL };
  uint8_t keys[N_HOPS][80];
  const int aesbits = 128;
  const size_t klen = cgo_key_material_len(aesbits);

  tt_assert(path);
  f = fopen(path, "w");
  tt_assert(f);
  tt_uint_op(klen, OP_EQ, sizeof(keys[0]));

  /* Forward direction: client originates, relays peel layers. */
  for (int h = 0; h < N_HOPS; ++h) {
    for (size_t i = 0; i < klen; ++i)
      keys[h][i] = (uint8_t)(i * 17 + h * 53 + 11);
    client[h] = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                              aesbits, keys[h], klen);
    relay[h] = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                             aesbits, keys[h], klen);
  }
  for (int trial = 0; trial < 12; ++trial) {
    const int target = trial % N_HOPS;
    cell_t cell;
    uint8_t wire[CELL_PAYLOAD_SIZE];
    uint8_t sendme[SENDME_TAG_LEN_CGO];
    memset(&cell, 0, sizeof(cell));
    cell.command = (trial & 1) ? CELL_RELAY : CELL_RELAY_EARLY;
    for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
      cell.payload[i] = (uint8_t)(trial + i * 29);

    const uint8_t *tag = NULL;
    cgo_crypt_client_originate(client[target], &cell, &tag);
    tt_assert(tag);
    memcpy(sendme, tag, sizeof(sendme));
    for (int h = target - 1; h >= 0; --h)
      cgo_crypt_client_forward(client[h], &cell);
    memcpy(wire, cell.payload, sizeof(wire));

    bool recognized = false;
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_relay_forward(relay[h], &cell, &tag);
      if (tag) {
        tt_int_op(h, OP_EQ, target);
        recognized = true;
        break;
      }
    }
    tt_assert(recognized);

    fprintf(f, "F %d %d %u wire=", trial, target,
            (unsigned)cell.command);
    cgo_trace_hex(f, wire, sizeof(wire));
    fprintf(f, " sendme=");
    cgo_trace_hex(f, sendme, sizeof(sendme));
    for (int h = 0; h < N_HOPS; ++h) {
      char label[4];
      tor_snprintf(label, sizeof(label), "c%d", h);
      cgo_trace_state(f, label, client[h]);
      tor_snprintf(label, sizeof(label), "r%d", h);
      cgo_trace_state(f, label, relay[h]);
      ASSERT_CGO_STATE_EQ(client[h], relay[h]);
    }
    fputc('\n', f);
  }
  for (int h = 0; h < N_HOPS; ++h) {
    cgo_crypt_free(client[h]);
    cgo_crypt_free(relay[h]);
  }

  /* Backward direction: one relay originates, client peels layers. */
  for (int h = 0; h < N_HOPS; ++h) {
    for (size_t i = 0; i < klen; ++i)
      keys[h][i] = (uint8_t)(i * 31 + h * 47 + 7);
    client[h] = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                              aesbits, keys[h], klen);
    relay[h] = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                             aesbits, keys[h], klen);
  }
  for (int trial = 0; trial < 12; ++trial) {
    const int origin = trial % N_HOPS;
    cell_t cell;
    uint8_t wire[CELL_PAYLOAD_SIZE];
    uint8_t sendme[SENDME_TAG_LEN_CGO];
    memset(&cell, 0, sizeof(cell));
    cell.command = (trial & 1) ? CELL_RELAY : CELL_RELAY_EARLY;
    for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
      cell.payload[i] = (uint8_t)(trial * 3 + i * 13);

    const uint8_t *tag = NULL;
    cgo_crypt_relay_originate(relay[origin], &cell, &tag);
    tt_assert(tag);
    memcpy(sendme, tag, sizeof(sendme));
    for (int h = origin - 1; h >= 0; --h)
      cgo_crypt_relay_backward(relay[h], &cell);
    memcpy(wire, cell.payload, sizeof(wire));

    bool recognized = false;
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_client_backward(client[h], &cell, &tag);
      if (tag) {
        tt_int_op(h, OP_EQ, origin);
        recognized = true;
        break;
      }
    }
    tt_assert(recognized);

    fprintf(f, "B %d %d %u wire=", trial, origin,
            (unsigned)cell.command);
    cgo_trace_hex(f, wire, sizeof(wire));
    fprintf(f, " sendme=");
    cgo_trace_hex(f, sendme, sizeof(sendme));
    for (int h = 0; h < N_HOPS; ++h) {
      char label[4];
      tor_snprintf(label, sizeof(label), "c%d", h);
      cgo_trace_state(f, label, client[h]);
      tor_snprintf(label, sizeof(label), "r%d", h);
      cgo_trace_state(f, label, relay[h]);
      ASSERT_CGO_STATE_EQ(client[h], relay[h]);
    }
    fputc('\n', f);
  }

 done:
  if (f)
    fclose(f);
  for (int h = 0; h < N_HOPS; ++h) {
    cgo_crypt_free(client[h]);
    cgo_crypt_free(relay[h]);
  }
  #undef N_HOPS
}

/**
 * Demonstrate the cryptographic consequence of recovering a complete live
 * CGO state at one instant.  The snapshot is represented as the current UIV
 * keys, nonce, and T'.  Those fields are evaluation ground truth supplied by
 * TOR_UNIT_TESTS; this test does not claim that production OpenSSL contexts
 * have already been decoded by the offline scanner.
 *
 * For forward cells, reconstruct relay-mode objects from the client's live
 * state and peel a subsequently emitted wire cell.  For backward cells,
 * reconstruct client-mode objects and peel the cell delivered to the client.
 */
static void
test_crypto_cgo_snapshot_replay(void *arg)
{
  (void)arg;
  #define N_HOPS 3
  const int aesbits = 128;
  const size_t klen = cgo_key_material_len(aesbits);
  uint8_t initial[N_HOPS][80];
  cgo_crypt_t *client[N_HOPS] = { NULL, NULL, NULL };
  cgo_crypt_t *relay[N_HOPS] = { NULL, NULL, NULL };
  cgo_crypt_t *clone[N_HOPS] = { NULL, NULL, NULL };

  tt_uint_op(klen, OP_EQ, 80);
  for (int h = 0; h < N_HOPS; ++h)
    for (size_t i = 0; i < klen; ++i)
      initial[h][i] = (uint8_t)(i * 37 + h * 71 + 13);

  /* Outbound: a snapshot taken before each cell decrypts that next cell. */
  for (int h = 0; h < N_HOPS; ++h) {
    client[h] = cgo_crypt_new(CGO_MODE_CLIENT_FORWARD,
                              aesbits, initial[h], klen);
    relay[h] = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                             aesbits, initial[h], klen);
  }
  for (int trial = 0; trial < 256; ++trial) {
    const int target = trial % N_HOPS;
    cell_t cell;
    cell_t plaintext;
    cell_t wire;
    memset(&cell, 0, sizeof(cell));
    cell.command = (trial & 1) ? CELL_RELAY : CELL_RELAY_EARLY;
    for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
      cell.payload[i] = (uint8_t)(trial * 11 + i * 19);
    memcpy(&plaintext, &cell, sizeof(cell));

    for (int h = 0; h < N_HOPS; ++h) {
      uint8_t state[80];
      memcpy(state, client[h]->uiv.uiv_keys_, 64);
      memcpy(state + 64, client[h]->nonce, 16);
      clone[h] = cgo_crypt_new(CGO_MODE_RELAY_FORWARD,
                               aesbits, state, sizeof(state));
      memcpy(clone[h]->tprime, client[h]->tprime, 16);
      memwipe(state, 0, sizeof(state));
    }

    const uint8_t *tag = NULL;
    cgo_crypt_client_originate(client[target], &cell, &tag);
    for (int h = target - 1; h >= 0; --h)
      cgo_crypt_client_forward(client[h], &cell);
    memcpy(&wire, &cell, sizeof(cell));

    bool forensic_recognized = false;
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_relay_forward(clone[h], &cell, &tag);
      if (tag) {
        tt_int_op(h, OP_EQ, target);
        forensic_recognized = true;
        break;
      }
    }
    tt_assert(forensic_recognized);
    tt_mem_op(cell.payload + SENDME_TAG_LEN_CGO, OP_EQ,
              plaintext.payload + SENDME_TAG_LEN_CGO,
              sizeof(cell.payload) - SENDME_TAG_LEN_CGO);

    /* Keep the real relay endpoint synchronized for the next snapshot. */
    memcpy(&cell, &wire, sizeof(cell));
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_relay_forward(relay[h], &cell, &tag);
      if (tag)
        break;
    }
    for (int h = 0; h < N_HOPS; ++h) {
      ASSERT_CGO_STATE_EQ(client[h], relay[h]);
      cgo_crypt_free(clone[h]);
    }
  }
  for (int h = 0; h < N_HOPS; ++h) {
    cgo_crypt_free(client[h]);
    cgo_crypt_free(relay[h]);
  }

  /* Inbound: reconstruct the client state and peel a future wire cell. */
  for (int h = 0; h < N_HOPS; ++h) {
    client[h] = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                              aesbits, initial[h], klen);
    relay[h] = cgo_crypt_new(CGO_MODE_RELAY_BACKWARD,
                             aesbits, initial[h], klen);
  }
  for (int trial = 0; trial < 256; ++trial) {
    const int origin = trial % N_HOPS;
    cell_t cell;
    cell_t plaintext;
    cell_t wire;
    memset(&cell, 0, sizeof(cell));
    cell.command = (trial & 1) ? CELL_RELAY : CELL_RELAY_EARLY;
    for (size_t i = SENDME_TAG_LEN_CGO; i < sizeof(cell.payload); ++i)
      cell.payload[i] = (uint8_t)(trial * 7 + i * 23);
    memcpy(&plaintext, &cell, sizeof(cell));

    for (int h = 0; h < N_HOPS; ++h) {
      uint8_t state[80];
      memcpy(state, client[h]->uiv.uiv_keys_, 64);
      memcpy(state + 64, client[h]->nonce, 16);
      clone[h] = cgo_crypt_new(CGO_MODE_CLIENT_BACKWARD,
                               aesbits, state, sizeof(state));
      memcpy(clone[h]->tprime, client[h]->tprime, 16);
      memwipe(state, 0, sizeof(state));
    }

    const uint8_t *tag = NULL;
    cgo_crypt_relay_originate(relay[origin], &cell, &tag);
    for (int h = origin - 1; h >= 0; --h)
      cgo_crypt_relay_backward(relay[h], &cell);
    memcpy(&wire, &cell, sizeof(cell));

    bool forensic_recognized = false;
    memcpy(&cell, &wire, sizeof(cell));
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_client_backward(clone[h], &cell, &tag);
      if (tag) {
        tt_int_op(h, OP_EQ, origin);
        forensic_recognized = true;
        break;
      }
    }
    tt_assert(forensic_recognized);
    tt_mem_op(cell.payload + SENDME_TAG_LEN_CGO, OP_EQ,
              plaintext.payload + SENDME_TAG_LEN_CGO,
              sizeof(cell.payload) - SENDME_TAG_LEN_CGO);

    memcpy(&cell, &wire, sizeof(cell));
    for (int h = 0; h < N_HOPS; ++h) {
      tag = NULL;
      cgo_crypt_client_backward(client[h], &cell, &tag);
      if (tag)
        break;
    }
    for (int h = 0; h < N_HOPS; ++h) {
      ASSERT_CGO_STATE_EQ(client[h], relay[h]);
      cgo_crypt_free(clone[h]);
    }
  }

 done:
  for (int h = 0; h < N_HOPS; ++h) {
    cgo_crypt_free(client[h]);
    cgo_crypt_free(relay[h]);
    cgo_crypt_free(clone[h]);
  }
  #undef N_HOPS
}

/** Replay one cell using states extracted from an external production core. */
static void
test_crypto_cgo_external_core_replay(void *arg)
{
  (void)arg;
  const char *fixture_path = getenv("CGO_REPLAY_FIXTURE");
  const char *result_path = getenv("CGO_REPLAY_RESULT");
  const char *negative_trials_env = getenv("CGO_REPLAY_NEGATIVE_TRIALS");
  const char *negative_mode = getenv("CGO_REPLAY_NEGATIVE_MODE");
  const bool expect_unrecognized =
    getenv("CGO_REPLAY_EXPECT_UNRECOGNIZED") != NULL;
  const char *unrecognized_label = getenv("CGO_REPLAY_UNRECOGNIZED_LABEL");
  unsigned long negative_trials = negative_trials_env ?
    strtoul(negative_trials_env, NULL, 10) : 0;
  FILE *f = NULL;
  FILE *result = NULL;
  cgo_crypt_t *clone[3] = { NULL, NULL, NULL };
  uint8_t header[8];
  uint8_t state[3][80];
  uint8_t tprime[3][16];
  uint8_t wire[CELL_PAYLOAD_SIZE];
  uint8_t plaintext[CELL_PAYLOAD_SIZE];
  bool fixture_has_truth = false;
  int hop_count = 0;
  cell_t cell;
  int recognized_hop = -1;
  unsigned long false_recognitions = 0;

  if (!fixture_path) {
    tt_skip();
  }
  f = fopen(fixture_path, "rb");
  tt_assert(f);
  tt_uint_op(fread(header, 1, sizeof(header), f), OP_EQ, sizeof(header));
  tt_assert(!memcmp(header, "CGR1", 4) || !memcmp(header, "CGR2", 4));
  fixture_has_truth = !memcmp(header, "CGR1", 4);
  hop_count = header[4];
  tt_int_op(hop_count, OP_GE, 1);
  tt_int_op(hop_count, OP_LE, 3);
  for (int h = 0; h < hop_count; ++h) {
    tt_uint_op(fread(state[h], 1, 80, f), OP_EQ, 80);
    tt_uint_op(fread(tprime[h], 1, 16, f), OP_EQ, 16);
  }
  tt_uint_op(fread(wire, 1, sizeof(wire), f), OP_EQ, sizeof(wire));
  if (fixture_has_truth) {
    tt_uint_op(fread(plaintext, 1, sizeof(plaintext), f), OP_EQ,
               sizeof(plaintext));
  }
  tt_int_op(fgetc(f), OP_EQ, EOF);
  fclose(f);
  f = NULL;

  if (negative_trials) {
    uint32_t prng = 0x6d2b79f5;
    for (unsigned long trial = 0; trial < negative_trials; ++trial) {
      memset(&cell, 0, sizeof(cell));
      cell.command = header[5];
      memcpy(cell.payload, wire, sizeof(wire));
      recognized_hop = -1;
      for (int h = 0; h < hop_count; ++h) {
        uint8_t wrong_state[80];
        uint8_t wrong_tprime[16];
        int source_hop =
          negative_mode && !strcmp(negative_mode, "hop_order") ?
          (h + 1) % hop_count : h;
        memcpy(wrong_state, state[source_hop], sizeof(wrong_state));
        memcpy(wrong_tprime, tprime[source_hop], sizeof(wrong_tprime));
        size_t mutation_offset = 0;
        if (negative_mode && !strcmp(negative_mode, "j_polyval")) {
          mutation_offset = 16;
        } else if (negative_mode && !strcmp(negative_mode, "s_aes")) {
          mutation_offset = 32;
        } else if (negative_mode && !strcmp(negative_mode, "s_polyval")) {
          mutation_offset = 48;
        } else if (negative_mode && !strcmp(negative_mode, "nonce")) {
          mutation_offset = 64;
        }
        /* Deterministically sample a different component for every hop/trial. */
        for (size_t i = 0; i < 16; ++i) {
          prng ^= prng << 13;
          prng ^= prng >> 17;
          prng ^= prng << 5;
          if (negative_mode && !strcmp(negative_mode, "tprime")) {
            wrong_tprime[i] ^= (uint8_t)(prng | 1);
          } else if (!negative_mode || strcmp(negative_mode, "hop_order")) {
            wrong_state[mutation_offset + i] ^= (uint8_t)(prng | 1);
          }
        }
        clone[h] = cgo_crypt_new(CGO_MODE_RELAY_FORWARD, 128,
                                 wrong_state, sizeof(wrong_state));
        memcpy(clone[h]->tprime, wrong_tprime, sizeof(wrong_tprime));
        const uint8_t *tag = NULL;
        cgo_crypt_relay_forward(clone[h], &cell, &tag);
        cgo_crypt_free(clone[h]);
        clone[h] = NULL;
        memwipe(wrong_state, 0, sizeof(wrong_state));
        if (tag) {
          recognized_hop = h;
          ++false_recognitions;
          break;
        }
      }
    }
    tt_u64_op((uint64_t)false_recognitions, OP_EQ, 0);
  } else {
    memset(&cell, 0, sizeof(cell));
    cell.command = header[5];
    memcpy(cell.payload, wire, sizeof(wire));
    for (int h = 0; h < hop_count; ++h) {
      clone[h] = cgo_crypt_new(CGO_MODE_RELAY_FORWARD, 128,
                               state[h], sizeof(state[h]));
      memcpy(clone[h]->tprime, tprime[h], sizeof(tprime[h]));
      const uint8_t *tag = NULL;
      cgo_crypt_relay_forward(clone[h], &cell, &tag);
      if (tag) {
        recognized_hop = h;
        break;
      }
    }
    if (expect_unrecognized) {
      tt_int_op(recognized_hop, OP_EQ, -1);
      if (fixture_has_truth) {
        tt_mem_op(cell.payload + SENDME_TAG_LEN_CGO, OP_NE,
                  plaintext + SENDME_TAG_LEN_CGO,
                  sizeof(plaintext) - SENDME_TAG_LEN_CGO);
      }
    } else if (fixture_has_truth) {
      tt_int_op(recognized_hop, OP_EQ, header[6]);
      tt_mem_op(cell.payload + SENDME_TAG_LEN_CGO, OP_EQ,
                plaintext + SENDME_TAG_LEN_CGO,
                sizeof(plaintext) - SENDME_TAG_LEN_CGO);
    }
  }

  if (result_path) {
    result = fopen(result_path, "w");
    tt_assert(result);
    if (negative_trials) {
      fprintf(result,
              "{\"schema\":\"tor-cgo-external-core-replay/0.1\","
              "\"negative_mode\":\"%s\",\"negative_trials\":%lu,"
              "\"false_recognitions\":%lu}\n",
              negative_mode ? negative_mode : "j_aes",
              negative_trials, false_recognitions);
    } else if (expect_unrecognized) {
      fprintf(result,
              "{\"schema\":\"tor-cgo-external-core-replay/0.1\","
              "\"recognized_hop\":%d,\"expected_unrecognized\":true,"
              "\"payload_match\":false,\"label\":\"%s\"}\n",
              recognized_hop,
              unrecognized_label ? unrecognized_label : "unspecified");
    } else if (fixture_has_truth) {
      fprintf(result,
              "{\"schema\":\"tor-cgo-external-core-replay/0.1\","
              "\"recognized_hop\":%d,\"expected_hop\":%u,"
              "\"payload_bytes_compared\":%u,\"payload_match\":true}\n",
              recognized_hop, (unsigned)header[6],
              (unsigned)(CELL_PAYLOAD_SIZE - SENDME_TAG_LEN_CGO));
    } else {
      fprintf(result,
              "{\"schema\":\"tor-cgo-external-core-replay/0.2\","
              "\"recognized_hop\":%d,\"recovered_payload_hex\":\"",
              recognized_hop);
      for (size_t i = 0; i < sizeof(cell.payload); ++i) {
        fprintf(result, "%02x", cell.payload[i]);
      }
      fprintf(result,
              "\",\"evaluation_truth_used\":false}\n");
    }
    fclose(result);
    result = NULL;
  }

 done:
  if (f)
    fclose(f);
  if (result)
    fclose(result);
  memwipe(state, 0, sizeof(state));
  for (int h = 0; h < 3; ++h)
    cgo_crypt_free(clone[h]);
}

struct testcase_t crypto_cgo_tests[] = {
  { "et_roundtrip", test_crypto_cgo_et_roundtrip, 0, NULL, NULL },
  { "et_testvec", test_crypto_cgo_et_testvec, 0, NULL, NULL },
  { "prf_testvec", test_crypto_cgo_prf_testvec, 0, NULL, NULL },
  { "uiv_roundtrip", test_crypto_cgo_uiv_roundtrip, 0, NULL, NULL },
  { "uiv_testvec", test_crypto_cgo_uiv_testvec, 0, NULL, NULL },
  { "uiv_update_testvec", test_crypto_cgo_uiv_update_testvec, 0, NULL, NULL },
  { "cgo_fwd", test_crypto_cgo_fwd, 0, NULL, NULL, },
  { "cgo_rev", test_crypto_cgo_rev, 0, NULL, NULL, },
  { "cgo_backward_ipr_resync", test_crypto_cgo_backward_ipr_resync,
    0, NULL, NULL, },
  { "cgo_backward_ipr_multihop_containment",
    test_crypto_cgo_backward_ipr_multihop_containment, 0, NULL, NULL, },
  { "cgo_state_sync_fwd", test_crypto_cgo_state_sync_fwd, 0, NULL, NULL, },
  { "cgo_state_sync_rev", test_crypto_cgo_state_sync_rev, 0, NULL, NULL, },
  { "cgo_tamper_fwd", test_crypto_cgo_tamper_fwd, 0, NULL, NULL, },
  { "cgo_tamper_rev", test_crypto_cgo_tamper_rev, 0, NULL, NULL, },
  { "cgo_tamper_command", test_crypto_cgo_tamper_command, 0, NULL, NULL, },
  { "cgo_sequence_faults", test_crypto_cgo_sequence_faults,
    0, NULL, NULL, },
  { "cgo_relay_testvec", test_crypto_cgo_relay_testvec, 0, NULL, NULL },
  { "cgo_relay_originate_testvec", test_crypto_cgo_relay_originate_testvec,
    0, NULL, NULL },
  { "cgo_client_originate_testvec", test_crypto_cgo_client_originate_testvec,
    0, NULL, NULL },
  { "cgo_cross_impl_trace", test_crypto_cgo_cross_impl_trace,
    0, NULL, NULL },
  { "cgo_snapshot_replay", test_crypto_cgo_snapshot_replay,
    0, NULL, NULL },
  { "cgo_external_core_replay", test_crypto_cgo_external_core_replay,
    0, NULL, NULL },
  END_OF_TESTCASES
};
