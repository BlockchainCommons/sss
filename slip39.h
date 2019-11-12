#ifndef SLIP39_H
#define SLIP39_H

#define RADIX_BITS 10
#define RADIX (1<<RADIX_BITS)
#define ID_LENGTH_BITS 15
#define ITERATION_EXP_LENGTH_BITS 5
#define ID_EXP_LENGTH_WORDS 2

#define bytes_to_words(n)  ( ( (n) * 8 + RADIX_BITS-1) / RADIX_BITS)
#define words_to_bytes(n)  ( ( (n) * RADIX_BITS ) / 8)

#define MAX_SHARD_COUNT 16
#define CHECKSUM_LENGTH_WORDS 3
#define DIGEST_LENGTH_BYTES 4

#define METADATA_LENGTH_WORDS 7
//(ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS)

#define MIN_STRENGTH_BYTES 16
#define MIN_MNEMONIC_LENGTH_WORDS (METADATA_LENGTH_WORDS + bytes_to_words(MIN_STRENGTH_BYTES) )

#define BASE_ITERATION_COUNT 2500
#define ROUND_COUNT 4
#define SECRET_INDEX 255
#define DIGEST_INDEX 254

#define SECRET_SIZE 32

#define ERROR_NOT_ENOUGH_MNEMONIC_WORDS        -1
#define ERROR_INVALID_MNEMONIC_CHECKSUM        -2
#define ERROR_INVALID_MNEMONIC_GROUP_THRESHOLD -3
#define ERROR_SECRET_TOO_SHORT                 -4
#define ERROR_SECRET_TOO_LONG                  -5
#define ERROR_INVALID_GROUP_THRESHOLD          -6
#define ERROR_INVALID_SINGLETON_MEMBER         -7
#define ERROR_INSUFFICIENT_SPACE               -8
#define ERROR_INVALID_SECRET_LENGTH            -9
#define ERROR_INVALID_PASSPHRASE              -10
#define ERROR_INVALID_SHARD_SET               -11
#define ERROR_EMPTY_MNEMONIC_SET              -12
#define ERROR_DUPLICATE_MEMBER_INDEX          -13
#define ERROR_NOT_ENOUGH_MEMBER_SHARDS        -14
#define ERROR_INVALID_MEMBER_THRESHOLD        -15
#define ERROR_TOO_MANY_SHARDS                 -16
#define ERROR_INTERPOLATION_FAILURE           -17
#define ERROR_CHECKSUM_FAILURE                -18
#define ERROR_INVALID_PADDING                 -19
#define ERROR_NOT_ENOUGH_GROUPS               -20
#define ERROR_INVALID_SHARD_BUFFER            -21

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


typedef struct group_descriptor_struct {
	uint8_t threshold;
	uint8_t count;
	const char **passwords;
} group_descriptor;

typedef struct slip39_shard_struct {
    uint16_t identifier;
    uint8_t iteration_exponent;
    uint8_t group_index;
    uint8_t group_threshold;
    uint8_t group_count;
    uint8_t member_index;
    uint8_t member_threshold;
    uint8_t value_length;
    uint8_t value[32];
} slip39_shard;

typedef struct group_struct {
	uint8_t group_index;
	uint8_t member_threshold;
	uint8_t count;
	uint8_t member_index[16];
	const uint8_t *value[16];
} slip39_group;

uint32_t rs1024_polymod(
	const uint16_t *values,    // values - 10 bit words
	uint32_t values_length // number of entries in the values array
);

void rs1024_create_checksum(
	uint16_t *values, // data words (10 bit)
	uint32_t n          // length of the data array, including three checksum word
);

uint8_t rs1024_verify_checksum(
	const uint16_t *values,  // data words
	uint32_t n         // length of the data array
);


// returns the 10-bit integer that a string represents, or -1
// if the string is not a code word.
int16_t lookup(const char *word);

const char *slip39_word(int16_t word);

/**
 * converts a string of whitespace delimited mnemonic words
 * to an array of 10-bit integers. Returns the number of integers
 * written to the buffer.
 *
 * returns: number of ints written to the words buffer
 *
 * inputs: word_string: space delimited group of mnemonic words
 * words: space to return results
 * words_length: maximum size of the words buffer
 */

uint32_t parse_words(
    const char *words_string,
    uint16_t *words,
    uint32_t words_length
);

/**
 * convert a buffer of bytes into 10-bit mnemonic words
 *
 * returns: the number of words written or -1 if there was an error
 *
 * inputs: buffer: byte buffer to encode into 10-bit words
 *         size: size of the buffer
 *         words: destination for the words
 *         max: maximum number of words to write
 */

int32_t to_words(
    const uint8_t *buffer, // byte buffer to encode into 10-bit words
    uint32_t size,   // buffer size
    uint16_t *words, // destination for words
    uint32_t max     // maximum number of words to write
);

/**
 * convert a buffer of words into bytes
 *
 * returns: the number of bytes written or a negative number if there was an error
 *
 * inputs: words: array of words to decode
 *         wordsise: number of elements in the words array
 *         buffer: memory location to write results to
 *         size: maximum number of bytes in the buffer.
 */
int32_t from_words(
    const uint16_t *words, // words to decode
    uint32_t wordsize,       // number of words to decode
    uint8_t *buffer,          // space for result
    size_t size            // total space available
);


/**
 * fills the destination buffer with count random bytes
 *
 * inputs: dest: location to write random bytes to
 *         count: number of bytes to write
 */
int randombytes(void *buf, size_t n);

/**
 * creates a digest used to help valididate secret reconstruction (see slip-39 docs)
 *
 * returns: a pointer to the resulting 4-byte digest
 * inputs: random_data: array of data to create a digest for
 *         rdlen: length of random_data array
 *         shared_secret: bytes to use as the key for the hmac when generating digest
 *         sslen: length of the shared secret array
 *         result: a pointer to a block of 4 bytes to store the resulting digest
 */
uint8_t* create_digest(
	const uint8_t *random_data,
	uint32_t rdlen,
	const uint8_t *shared_secret,
	uint32_t sslen,
	uint8_t *result
);

//////////////////////////////////////////////////
// slip39 shamir sharing

/**
 * used slip39's version of shamir sharing to split a secret up into
 * shard_count shares such that threshold of them must be presented
 * to recover the secret.
 *
 * returns: the number of shards created
 *
 * inputs: threshold: number of shards required to recover secret
 *         shard_count: number of shards to generate
 *         secret: array of bytes representing the secret
 *         secret_length: length of the secret array. must be >= 16, <= 32 and even.
 *         result: place to store the resulting shares. Must be able to hold
 *                 share_count * secret_length bytes.
 */
int32_t split_secret(
	uint8_t threshold,
	uint8_t shard_count,
	const uint8_t *secret,
	uint32_t secret_length,
	uint8_t *result
);

/**
 * recover a secret from shards
 *
 * returns: the number of bytes written to the secret array, or a negative value if there was an error
 *
 * inputs: threshold: number of shards required
 *         x: array of x values  (length threshold)
 *         shards: array (length threshold) of pointers to y value arrays
 *         shard_length: number of bytes in each y value array
 *         secret: array for writing results (must be at least shard_length long)
 */
int32_t recover_secret(
	uint8_t threshold,
	const uint8_t *x,
	const uint8_t **shards,
	uint32_t shard_length,
	uint8_t *secret
);

/**
 * this is the round function described in the slip39 spec for the Fiestel network
 * it uses to encrypt/decrypt secrets with a passphrase
 *
 * inputs: i: round number
 *         passphrase: ascii encoded passphrase
 *         exp: exponent for the number of iterations of pbkd to run
 *         salt: array of bytes to use a salt for the encryption
 *         salt_lentgh: length of the salt array
 *         r: array of bytes to encrypt
 *         r_length: lenght of the r array
 *         dest: location to store encrypted value
 *         dest_length: maximum number of bytes to write to dest
 */
void round_function(
	uint8_t i,
	const char *passphrase,
	uint8_t exp,
	const uint8_t *salt,
	uint32_t salt_length,
	const uint8_t *r,
	uint32_t r_length,
	uint8_t *dest,
	uint32_t dest_length
);

/**
 * encrypts input using passphrase with the Fiestel network described in the slip39 spec
 *
 * inputs:  input: array of bytes to encrypt
 *          input_length: length of input array
 *          passphrase: null terminated ascii string
 *          iteration_exponent: exponent for the number of pbkd rounds to use
 *          identifier: identifier for the shard set (used as part of the salt)
 *          output: memory location to write output to (same length as the input)
 */
void slip39_encrypt(
	const uint8_t *input,
	uint32_t input_length,
	const char *passphrase,
	uint8_t iteration_exponent,
	uint16_t identifier,
	uint8_t *output
);

/**
 * decrypts input using passphrase with the Fiestel network described in the slip39 spec
 *
 * inputs:  input: array of bytes to decrypt
 *          input_length: length of input array
 *          passphrase: null terminated ascii string
 *          iteration_exponent: exponent for the number of pbkd rounds to use
 *          identifier: identifier for the shard set (used as part of the salt)
 *          output: memory location to write output to (same length as the input)
 */
void slip39_decrypt(
	const uint8_t *input,
	uint32_t input_length,
	const char *passphrase,
	uint8_t iteration_exponent,
	uint16_t identifier,
	uint8_t *output
);

/**
 * encodes a shard as a mnemonic
 *
 * returns: number of mnemonic words generated on success, or a negative error code on failure.
 *
 * inputs: shard: pointer to a slip39_shard structure
 *         destination: array of 16bit integers to write resulting mnemonic codes to
 *         destination_length: maximum number of integers to write
 */
int encode_mnemonic(
    const slip39_shard *shard,
    uint16_t *destination,
    uint32_t destination_length
);

/**
 * decodes set of mnemonic codes as a slip39_shard structure
 *
 * returns: the length of the shard's secret on success or a negative error code on failure.
 *
 * inputs: mnemonic: array of 16-bit integers representing mnemonic codes
 *         mnemonic_lentgh: lenght of mnemonic array
 *         share: pointer to a shard structure to write results
 */
int decode_mnemonic(
	const uint16_t *mnemonic,
	uint32_t mnemonic_length,
	slip39_shard *shard
);

/**
 * diagnostic function for writing out hexidecimal encoded byte buffer.
 *
 * inputs: buffer: the buffer to display
 *         length: number of bytes to display
 */
void print_hex(
    const uint8_t *buffer,
    uint32_t length
);

/**
 * prints out string representation of a mnemonic code
 *
 * inputs: mnemonic: array of integers
 *         mnemonic_length: length of mnemonic array
 */
void print_mnemonic(
    const uint16_t *mnemonic,
    unsigned int mnemonic_length
);

/**
 * generate a set of shards that can be used to reconstuct a secret
 * using the given group policy
 *
 * returns: the number of shards generated if successful,
 *          or a negative number indicating an error code when unsuccessful
 *
 * inputs: group_threshold: the number of groups that need to be satisfied in order
 *                          to reconstruct the secret
 *         groups: an array of group descriptors
 *         groups_length: the length of the groups array
 *         master_secret: pointer to the secret to split up
 *         master_secret_length: length of the master secret in bytes.
 *                               must be >= 16, <= 32, and even.
 *         passphrase: string to use to encrypt the master secret
 *         iteration_exponent: exponent to use when calculating the number of rounds of encryption
 *                             to go through when encrypting the master secret.
 *         shards: array of shard structures to store the resulting shards
 *         shards_size: length of the shards array
 */

int generate_shards(
    uint8_t group_threshold,
    const group_descriptor *groups,
    uint8_t groups_length,
    const uint8_t *master_secret,
    uint32_t master_secret_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    slip39_shard *shards,
    uint16_t shards_size
);

/**
 * combine a set of shards to reconstuct a secret
 *
 * returns: the length of the reconstructed secret if successful
 *          or a negative number indicating an error code when unsuccessful
 *
 * inputs: shards: an array of shards to combine
 *         shards_count: length of the shards array
 *         passphrase: passphrase to use encrypt the resulting secret
 *         passwords: array of strings to use to decrypt shard data
 *                    passing NULL disables password decrypt for all shards
 *                    passing NULL for the ith password will disable decrypt for the ith shard
 *                    passing a pointer to a string for the ith shard will cause the ith shard
 *                    to be decrypted with the string before recombination
 *         buffer: location to store the result
 *         buffer_length: maximum space available in buffer
 */

int combine_shards(
    const slip39_shard *shards, // array of shard structures
    uint16_t shards_count,      // number of shards in array
    const char *passphrase,     // passphrase to unlock master secret
    const char **passwords,     // passwords for the shards
    uint8_t *buffer,            // working space, and place to return secret
    uint32_t buffer_length      // total amount of working space
);


/**
 * generate a set of shards that can be used to reconstuct a secret
 * using the given group policy, but encode them as mnemonic codes
 *
 * returns: the number of shards generated if successful,
 *          or a negative number indicating an error code when unsuccessful
 *
 * inputs: group_threshold: the number of groups that need to be satisfied in order
 *                          to reconstruct the secret
 *         groups: an array of group descriptors
 *         groups_length: the length of the groups array
 *         master_secret: pointer to the secret to split up
 *         master_secret_length: length of the master secret in bytes.
 *                               must be >= 16, <= 32, and even.
 *         passphrase: string to use to encrypt the master secret
 *         iteration_exponent: exponent to use when calculating the number of rounds of encryption
 *                             to go through when encrypting the master secret.
 *         mnemonic_length: pointer to an integer that will be filled with the number of
 *                          mnemonic words in each shard
 *         mnemonics: array of shard structures to store the resulting mnemonics.
 *                    the ith shard will be represented by
 *                     mnemonics[i*mnemonic_length]..mnemonics[(i+1)*mnemonic_length -1]
 *         buffer_size: maximum number of mnemonics code to write to the mnemonics array
 */
int generate_mnemonics(
	uint8_t group_threshold,
	const group_descriptor *groups,
	uint8_t groups_length,
	const uint8_t *master_secret,
	uint32_t master_secret_length,
	const char *passphrase,
	uint8_t iteration_exponent,
	uint32_t *mnemonic_length,
	uint16_t *mnemonics,
	uint32_t buffer_size
);


/**
 * combine a set of mnemonic encoded shards to reconstuct a secret
 *
 * returns: the length of the reconstructed secret if successful
 *          or a negative number indicating an error code when unsuccessful
 *
 * inputs: mnemonics: an array of pointers to arrays of mnemonic codes
 *         mnemonics_words: length of each array of mnemonic codes\
 *         mnemonics_shards: length of the mnemonics array
 *         passphrase: passphrase to use encrypt the resulting secret
 *         passwords: array of strings to use to decrypt shard data
 *                    passing NULL disables password decrypt for all shards
 *                    passing NULL for the ith password will disable decrypt for the ith shard
 *                    passing a pointer to a string for the ith shard will cause the ith shard
 *                    to be decrypted with the string before recombination
 *         buffer: location to store the result
 *         buffer_length: maximum space available in buffer
 */
int combine_mnemonics(
	const uint16_t **mnemonics, // array of pointers to 10-bit words
	uint32_t mnemonics_words,   // number of words in each shard
	uint32_t mnemonics_shards,  // total number of shards
	const char *passphrase,     // passphrase to unlock master secret
	const char **passwords,     // passwords protecting shards
	uint8_t *buffer,            // working space, and place to return secret
	uint32_t buffer_length      // total amount of working space
);

/**
 * encrypt the share value of a shard
 *
 * inputs: shard: the shard to encrypt. The shard value is modified in place.
 *         passphrase: a NULL terminated ascii string to use to encrypt the shard
 */
void encrypt_shard(
    slip39_shard *shard,
    const char *passphrase
);

/**
 * decrypt the share value of a shard
 *
 * inputs: shard: the shard to decrypt. The shard value is modified in place.
 *         passphrase: a NULL terminated ascii string to use to decrypt the shard
 */
void decrypt_shard(
    slip39_shard *shard,
    const char *passphrase
);


/**
 * decode a slip39 shard encoded in a binary buffer
 *
 * returns: if nothing went wrong, the number of bytes read from the buffer
 *          if an error ocurred, a negative number indicating one of the following
 *          error conditions:
 *            ERROR_INVALID_SHARD_BUFFER
 *            ERROR_SECRET_TOO_SHORT
 *            ERROR_SECRET_TOO_LONG
 *
 * inputs: shard: a pointer so a slip39_shard which will be populated upon success.
 *         buffer: a byte buffer containing a binary encoded shard
 *         buffer_length: the length of the buffer
 */

int decode_binary_shard(
    slip39_shard *shard,
    const uint8_t *buffer,
    uint32_t buffer_length
);

/**
 * encode a slip39 shard into a binary buffer
 *
 * returns: if nothing went wrong, the number of bytes read from the buffer
 *          if an error ocurred, a negative number indicating one of the following
 *          error conditions:
 *            ERROR_INVALID_SHARD_BUFFER
 *
 * inputs: shard: a pointer so a slip39_shard which will be populated upon success.
 *         buffer: a byte buffer containing a binary encoded shard
 *         buffer_length: the length of the buffer
 */
int encode_binary_shard(
    uint8_t *buffer,
    uint32_t buffer_length,
    const slip39_shard *shard
);

#endif
