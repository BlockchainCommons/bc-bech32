//
//  test.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>

#include "../src/bc-bech32.h"
#include "test-utils.h"

static const char* valid_checksum[] = {
    "A12UEL5L",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
};

static const char* invalid_checksum[] = {
    " 1nwldj5",
    "\x7f""1axkwrx",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
};

struct valid_address_data {
    const char* address;
    size_t scriptPubKeyLen;
    const uint8_t scriptPubKey[42];
};

struct invalid_address_data {
    const char* hrp;
    int version;
    size_t program_length;
};

static struct valid_address_data valid_address[] = {
    {
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        22, {
            0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        }
    },
    {
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        34, {
            0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
            0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
            0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
            0x62
        }
    },
    {
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
        42, {
            0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
            0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        }
    },
    {
        "BC1SW50QA3JX3S",
        4, {
           0x60, 0x02, 0x75, 0x1e
        }
    },
    {
        "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
        18, {
            0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
        }
    },
    {
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        34, {
            0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
            0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
            0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
            0x33
        }
    }
};

static const char* invalid_address[] = {
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "bca0w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90234567789035",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu",
};

static struct invalid_address_data invalid_address_enc[] = {
    {"BC", 0, 20},
    {"bc", 0, 21},
    {"bc", 17, 32},
    {"bc", 1, 1},
    {"bc", 16, 41},
};

struct valid_seed_data {
    const char* encoded_seed;
    size_t seed_len;
    const uint8_t seed[64];
};

static struct valid_seed_data valid_seed[] = {
    {
        "chl9xyj538m0tsjglhpnf4a6nfdphnn9nc4w4ulq5gfv8eppvftl6ew3wez55hean67urzgq95tyrval5q3wal8h9acdjr6lwc7rrwqapat22",
        64,
        {
            0xc5, 0xfe, 0x53, 0x12, 0x54, 0x89, 0xf6, 0xf5,
            0xc2, 0x48, 0xfd, 0xc3, 0x34, 0xd7, 0xba, 0x9a, 
            0x5a, 0x1b, 0xce, 0x65, 0x9e, 0x2a, 0xea, 0xf3, 
            0xe0, 0xa2, 0x12, 0xc3, 0xe4, 0x21, 0x62, 0x57, 
            0xfd, 0x65, 0xd1, 0x76, 0x45, 0x4a, 0x5f, 0x3d, 
            0x9e, 0xbd, 0xc1, 0x89, 0x00, 0x2d, 0x16, 0x41, 
            0xb3, 0xbf, 0xa0, 0x22, 0xee, 0xfc, 0xf7, 0x2f,
            0x70, 0xd9, 0x0f, 0x5f, 0x76, 0x3c, 0x31, 0xb8
        }
    }
};

static void segwit_scriptpubkey(uint8_t* scriptpubkey, size_t* scriptpubkeylen, int witver, const uint8_t* witprog, size_t witprog_len) {
    scriptpubkey[0] = witver ? (0x50 + witver) : 0;
    scriptpubkey[1] = witprog_len;
    memcpy(scriptpubkey + 2, witprog, witprog_len);
    *scriptpubkeylen = witprog_len + 2;
}

int my_strncasecmp(const char *s1, const char *s2, size_t n) {
    size_t i = 0;
    while (i < n) {
        char c1 = s1[i];
        char c2 = s2[i];
        if (c1 >= 'A' && c1 <= 'Z') c1 = (c1 - 'A') + 'a';
        if (c2 >= 'A' && c2 <= 'Z') c2 = (c2 - 'A') + 'a';
        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
        if (c1 == 0) return 0;
        ++i;
    }
    return 0;
}

int main(void) {
    size_t i;
    int fail = 0;
    for (i = 0; i < sizeof(valid_checksum) / sizeof(valid_checksum[0]); ++i) {
        uint8_t data[82];
        char rebuild[92];
        char hrp[84];
        size_t data_len;
        int ok = 1;
        if (!bech32_decode(hrp, data, &data_len, valid_checksum[i], version_bech32)) {
            printf("bech32_decode fails: '%s'\n", valid_checksum[i]);
            ok = 0;
        }
        if (ok) {
            if (!bech32_encode(rebuild, hrp, data, data_len, version_bech32)) {
                printf("bech32_encode fails: '%s'\n", valid_checksum[i]);
                ok = 0;
            }
        }
        if (ok && my_strncasecmp(rebuild, valid_checksum[i], 92)) {
            printf("bech32_encode produces incorrect result: '%s'\n", valid_checksum[i]);
            ok = 0;
        }
        fail += !ok;
    }
    for (i = 0; i < sizeof(invalid_checksum) / sizeof(invalid_checksum[0]); ++i) {
        uint8_t data[82];
        char hrp[84];
        size_t data_len;
        int ok = 1;
        if (bech32_decode(hrp, data, &data_len, invalid_checksum[i], version_bech32)) {
            printf("bech32_decode succeeds on invalid string: '%s'\n", invalid_checksum[i]);
            ok = 0;
        }
        fail += !ok;
    }
    for (i = 0; i < sizeof(valid_address) / sizeof(valid_address[0]); ++i) {
        uint8_t witprog[40];
        size_t witprog_len;
        int witver;
        const char* hrp = "bc";
        int ok = 1;
        uint8_t scriptpubkey[42];
        size_t scriptpubkey_len;
        char rebuild[93];
        int ret = segwit_addr_decode(&witver, witprog, &witprog_len, hrp, valid_address[i].address, version_bech32);
        if (!ret) {
            hrp = "tb";
            ret = segwit_addr_decode(&witver, witprog, &witprog_len, hrp, valid_address[i].address, version_bech32);
        }
        if (!ret) {
            printf("segwit_addr_decode fails: '%s'\n", valid_address[i].address);
            ok = 0;
        }
        if (ok) segwit_scriptpubkey(scriptpubkey, &scriptpubkey_len, witver, witprog, witprog_len);
        if (ok && (scriptpubkey_len != valid_address[i].scriptPubKeyLen || memcmp(scriptpubkey, valid_address[i].scriptPubKey, scriptpubkey_len))) {
            printf("segwit_addr_decode produces wrong result: '%s'\n", valid_address[i].address);
            ok = 0;
        }
        if (ok && !segwit_addr_encode(rebuild, hrp, witver, witprog, witprog_len, version_bech32)) {
            printf("segwit_addr_encode fails: '%s'\n", valid_address[i].address);
            ok = 0;
        }
        if (ok && my_strncasecmp(valid_address[i].address, rebuild, 93)) {
            printf("segwit_addr_encode produces wrong result: '%s'\n", valid_address[i].address);
            ok = 0;
        }
        fail += !ok;
    }
    for (i = 0; i < sizeof(invalid_address) / sizeof(invalid_address[0]); ++i) {
        uint8_t witprog[40];
        size_t witprog_len;
        int witver;
        int ok = 1;
        if (segwit_addr_decode(&witver, witprog, &witprog_len, "bc", invalid_address[i], version_bech32)) {
            printf("segwit_addr_decode succeeds on invalid address '%s'\n", invalid_address[i]);
            ok = 0;
        }
        if (segwit_addr_decode(&witver, witprog, &witprog_len, "tb", invalid_address[i], version_bech32)) {
            printf("segwit_addr_decode succeeds on invalid address '%s'\n", invalid_address[i]);
            ok = 0;
        }
        fail += !ok;
    }
    for (i = 0; i < sizeof(invalid_address_enc) / sizeof(invalid_address_enc[0]); ++i) {
        char rebuild[93];
        static const uint8_t program[42] = {0};
        if (segwit_addr_encode(rebuild, invalid_address_enc[i].hrp, invalid_address_enc[i].version, program, invalid_address_enc[i].program_length, version_bech32)) {
            printf("segwit_addr_encode succeeds on invalid input '%s'\n", rebuild);
            ++fail;
        }
    }
    for (i = 0; i < sizeof(valid_seed) / sizeof(valid_seed[0]); ++i) {
        char output[120];
        bool ok = true;
        if(ok && !bc32_seed_encode(output, valid_seed[i].seed, valid_seed[i].seed_len)) {
            printf("seed encode fails.\n");
            ok = false;
        }
        //printf("seed: \"%s\"\n", output);
        if(ok && strcmp(output, valid_seed[i].encoded_seed) != 0) {
            printf("seed encode doesn't match.\n");
            ok = false;
        }
        
        uint8_t rebuild[70];
        size_t seed_len;
        if(ok && !bc32_seed_decode(rebuild, &seed_len, valid_seed[i].encoded_seed)) {
            printf("seed decode fails.\n");
            ok = false;
        }
        if(ok && !equal_uint8_buffers(rebuild, seed_len, valid_seed[i].seed, valid_seed[i].seed_len)) {
            printf("seed decode doesn't match.\n");
            ok = false;
        }
        if (!ok) {
            fail++;
        }
    }
    if(fail > 0) {
        printf("%i failures\n", fail);
    }
    return fail != 0;
}
