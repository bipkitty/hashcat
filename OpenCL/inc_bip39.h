/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_BIP39_H
#define INC_BIP39_H

// end of the mnemonic in salt
#define MNEMONIC_END (0x1FFFFFFF)
// encoding error
#define MNEMONIC_ERROR (0x2FFFFFFF)
// '?' will be guess in password
#define MNEMONIC_GUESS (0x3FFFFFFF)
// Indicates to display the seed word when cracked
#define MNEMONIC_DISPLAY (0x90000000)

// end of derivation path
#define DERIVATION_END (0x5FFFFFFF)
// encoding error
#define DERIVATION_ERROR (0x6FFFFFFF)
// guess up until the next number
#define DERIVATION_GUESS (0x7FFFFFFF)
// guess up until the next number
#define DERIVATION_SEPARATOR (0x8FFFFFFF)
// indicates a hardened path XOR with the path
#define DERIVATION_HARDENED (0x80000000)

// Start of BIP-39 xbit charsets
#define BIP39_BYTE_OFFSET (48)

// Address (digest) encoding types
#define XPUB_ADDRESS_ID (0)
#define P2PKH_ADDRESS_ID (1)
#define P2SHWPKH_ADDRESS_ID (2)
#define P2WPKH_ADDRESS_ID (3)

// Max derivation path len and stores the index into the salt
#define PATH_LEN 10

// BIP-39 variables that store the iterations of PBKDF2-SHA512
typedef struct bip39_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[16];
  u64 out[16];

  u32 salt_index;

  u32 derivation_path[PATH_LEN + 1];

} bip39_tmp_t;

// Represents the current state of encoding a message
typedef struct msg_encoder
{
  u32 bitwise_offset;
  u32 index;
  u32 *output;
  u32 len;
} msg_encoder_t;

DECLSPEC msg_encoder_t encoder_init (PRIVATE_AS u32 * output);
DECLSPEC void encode_char (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u8 c);
DECLSPEC void encode_array_be (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 * array, PRIVATE_AS const u32 len, PRIVATE_AS const u32 start_index);
DECLSPEC void encode_array_le (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 * array, PRIVATE_AS const u32 len, PRIVATE_AS const u32 start_index);
DECLSPEC void encode_mnemonic_word (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 word_index);
DECLSPEC void encode_mnemonic_phrase (PRIVATE_AS msg_encoder_t * encoder, PRIVATE_AS const u32 * words);
DECLSPEC u32 bip39_guess_words (PRIVATE_AS const u32 * password, PRIVATE_AS const u32 * salt, PRIVATE_AS u32 * wordlist);
DECLSPEC u32 bip39_from_word (PRIVATE_AS const char *word);

#endif // INC_BIP39_H
