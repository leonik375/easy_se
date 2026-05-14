#include "tunnel.hpp"
#include "pack.hpp"
#include "sha0.hpp"
#include "vpn_internal.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <cctype>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define DBG(...) do { if (vpn_debug()) fprintf(stderr, __VA_ARGS__); } while(0)

/* -------------------------------------------------------------------------
   UDP acceleration helpers
   ------------------------------------------------------------------------- */

static uint64_t monotonic_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

static void rc4_crypt(uint8_t *dst, const uint8_t *src, size_t len,
                      const uint8_t *key, size_t keylen)
{
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = static_cast<uint8_t>(i);
    for (int i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 255;
        std::swap(S[i], S[j]);
    }
    size_t ri = 0, rj = 0;
    for (size_t n = 0; n < len; n++) {
        ri = (ri + 1) & 255;
        rj = (rj + S[ri]) & 255;
        std::swap(S[ri], S[rj]);
        dst[n] = src[n] ^ S[(S[ri] + S[rj]) & 255];
    }
}

/* V1 per-packet key: SHA1(common_key[20] || iv[20]) */
static void udp_v1_pkt_key(uint8_t *out, const uint8_t *key, const uint8_t *iv)
{
    uint8_t tmp[40];
    memcpy(tmp, key, 20); memcpy(tmp + 20, iv, 20);
    SHA1(tmp, 40, out);
}

static uint64_t rd_be64(const uint8_t *p) {
    return (uint64_t)p[0]<<56|(uint64_t)p[1]<<48|(uint64_t)p[2]<<40|(uint64_t)p[3]<<32
          |(uint64_t)p[4]<<24|(uint64_t)p[5]<<16|(uint64_t)p[6]<<8|(uint64_t)p[7];
}
static void wr_be64(uint8_t *p, uint64_t v) {
    p[0]=(v>>56)&0xff; p[1]=(v>>48)&0xff; p[2]=(v>>40)&0xff; p[3]=(v>>32)&0xff;
    p[4]=(v>>24)&0xff; p[5]=(v>>16)&0xff; p[6]=(v>>8)&0xff;  p[7]=v&0xff;
}

/* -------------------------------------------------------------------------
   WaterMark: SoftEther's protocol signature (a valid GIF89a image).
   The server checks that the POST body starts with this byte sequence.
   Source: SoftEther VPN WaterMark.c
   ------------------------------------------------------------------------- */
static const uint8_t kWaterMark[] = {
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xC8, 0x00, 0x33, 0x00, 0xF2, 0x00, 0x00, 0x36, 0x37, 0x34,
    0x79, 0x68, 0x54, 0x80, 0x80, 0x80, 0xAF, 0x7F, 0x5B, 0xB3, 0xA8, 0x9D, 0xD5, 0xD5, 0xD4, 0xFF,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x33, 0x00, 0x00, 0x03,
    0xFE, 0x08, 0x1A, 0xDC, 0x34, 0x0A, 0x04, 0x41, 0x6B, 0x65, 0x31, 0x4F, 0x11, 0x80, 0xF9, 0x60,
    0x28, 0x8E, 0x64, 0x69, 0x9E, 0x68, 0xAA, 0xAE, 0x6C, 0xEB, 0x9A, 0x4B, 0xE3, 0x0C, 0x0C, 0x25,
    0x6F, 0x56, 0xA7, 0xE9, 0xD2, 0xEB, 0xFF, 0xC0, 0xA0, 0x70, 0xC8, 0x8A, 0xDC, 0x2C, 0x9C, 0xC6,
    0x05, 0xC7, 0x31, 0x66, 0x24, 0x04, 0xA2, 0x74, 0x4A, 0xAD, 0x4E, 0x05, 0xB1, 0x0D, 0x61, 0xCB,
    0x25, 0xD4, 0xB8, 0x49, 0x1B, 0xE6, 0x19, 0xB1, 0x9A, 0xCF, 0xE8, 0xF4, 0x07, 0x2B, 0x11, 0x74,
    0x09, 0x85, 0x78, 0xFC, 0x0D, 0x6E, 0x90, 0x9F, 0xEA, 0x02, 0x81, 0x12, 0x35, 0xEF, 0x29, 0x6A,
    0x81, 0x2C, 0x04, 0x0A, 0x6E, 0x5C, 0x72, 0x88, 0x7A, 0x7A, 0x6F, 0x4D, 0x77, 0x19, 0x25, 0x71,
    0x16, 0x71, 0x2F, 0x05, 0x92, 0x06, 0x95, 0x80, 0x22, 0x48, 0x16, 0x7D, 0x98, 0x02, 0x9A, 0x7C,
    0x82, 0x06, 0x16, 0x23, 0x7F, 0x02, 0x05, 0x6B, 0x48, 0x70, 0x23, 0x15, 0x7D, 0x1F, 0x98, 0xA8,
    0x21, 0x7F, 0x87, 0x89, 0xB5, 0x8B, 0x7C, 0x7B, 0x3C, 0x8E, 0x23, 0x9E, 0x9B, 0xAE, 0x2B, 0xAD,
    0x20, 0xA6, 0xAC, 0x9B, 0x14, 0xB1, 0xC3, 0x21, 0x15, 0xB1, 0x81, 0x9E, 0x22, 0x9E, 0xAE, 0xC5,
    0x99, 0x20, 0x96, 0xAF, 0xC6, 0xA0, 0x70, 0xB6, 0xB6, 0x5B, 0x03, 0x1C, 0x16, 0x8E, 0x65, 0x21,
    0xBD, 0x9B, 0xCB, 0x2A, 0x9E, 0xCB, 0xC1, 0xE1, 0xD1, 0xA7, 0xA9, 0x6E, 0xE9, 0xD6, 0x82, 0xCD,
    0xC9, 0xCA, 0xD5, 0xD1, 0xAE, 0xBD, 0xCB, 0x7F, 0xAC, 0xB4, 0xD9, 0x73, 0x34, 0x37, 0x76, 0xDF,
    0x3C, 0xC8, 0x9A, 0x07, 0x42, 0x4E, 0x38, 0x4C, 0xAB, 0x0A, 0xFA, 0x12, 0x17, 0xEA, 0x52, 0x05,
    0x12, 0x0C, 0xDB, 0x35, 0xD3, 0xF3, 0xCE, 0xD9, 0x2C, 0x72, 0x13, 0xB7, 0x40, 0x22, 0xE8, 0xFE,
    0xB0, 0x61, 0xC7, 0x4F, 0xEC, 0x40, 0x7E, 0x94, 0xF6, 0x50, 0x13, 0x36, 0x83, 0xA8, 0x6A, 0x79,
    0xF9, 0x77, 0xE3, 0x1B, 0x28, 0x69, 0x1B, 0x55, 0x09, 0x1B, 0x67, 0x8A, 0x1A, 0xA9, 0x52, 0xC5,
    0x50, 0x71, 0x42, 0x82, 0x31, 0xDA, 0xB4, 0x56, 0x15, 0x9D, 0x71, 0xBC, 0x19, 0xF2, 0x27, 0x49,
    0x3E, 0xEF, 0x3C, 0x4E, 0xDB, 0x92, 0xED, 0x52, 0xBF, 0x01, 0xFE, 0x02, 0x44, 0x95, 0xB1, 0x6B,
    0xA0, 0x32, 0x72, 0x0A, 0x25, 0x72, 0x1C, 0xE5, 0x11, 0x99, 0x3C, 0x5F, 0x33, 0x61, 0x72, 0x75,
    0x93, 0x92, 0x28, 0x42, 0xA3, 0x7D, 0x72, 0x9A, 0x20, 0x68, 0x8A, 0x1C, 0x3A, 0x73, 0x3F, 0xE1,
    0x84, 0x82, 0x55, 0xEA, 0xE4, 0xA5, 0xBB, 0x89, 0xDE, 0x4C, 0x60, 0x30, 0x75, 0x0C, 0x9E, 0x97,
    0xD4, 0x8C, 0xC6, 0x32, 0x3B, 0xB4, 0x64, 0xD6, 0x71, 0x46, 0x45, 0x7E, 0x3C, 0x67, 0xB8, 0x30,
    0x20, 0xB8, 0x29, 0x82, 0x3D, 0x73, 0xE7, 0x93, 0x1E, 0xAA, 0x3F, 0x91, 0xD6, 0x89, 0x60, 0x9A,
    0xC8, 0x69, 0x36, 0xA8, 0x1B, 0xA4, 0xFE, 0x23, 0x03, 0x51, 0xED, 0xC7, 0xC4, 0x87, 0x19, 0xB7,
    0xA3, 0xCC, 0x13, 0x2D, 0x65, 0xD5, 0xB1, 0x22, 0x4A, 0xDE, 0xBA, 0xF6, 0xA1, 0x57, 0x7A, 0x0B,
    0xB3, 0x96, 0x3D, 0x95, 0xAF, 0x2E, 0x4A, 0xBC, 0x2A, 0xB9, 0x25, 0x61, 0x09, 0x10, 0x1C, 0x24,
    0x53, 0x7D, 0xBC, 0xA2, 0x33, 0xE0, 0x15, 0x72, 0x58, 0xC5, 0xAF, 0xAD, 0x8A, 0x84, 0x5C, 0x13,
    0xF1, 0xED, 0x13, 0xE6, 0x68, 0x57, 0x3F, 0x85, 0xB5, 0xF7, 0x58, 0xC3, 0xB2, 0x3A, 0xA7, 0x54,
    0xB9, 0x87, 0x86, 0x98, 0xBD, 0xA3, 0x8D, 0xD7, 0xCE, 0x44, 0xD4, 0xF1, 0x74, 0xDA, 0x44, 0x85,
    0x06, 0x25, 0x7C, 0x54, 0xEC, 0x57, 0xE8, 0x26, 0x18, 0xFE, 0x2A, 0xBA, 0xFE, 0xB9, 0xFE, 0xE6,
    0xCD, 0x88, 0x00, 0x57, 0x0B, 0x54, 0xFE, 0x20, 0x31, 0x1A, 0x0F, 0x01, 0x14, 0x94, 0xD0, 0x61,
    0x69, 0x95, 0x14, 0x0F, 0x3B, 0xAE, 0x5C, 0x37, 0x16, 0x56, 0xCF, 0xBD, 0x14, 0xA1, 0x61, 0x12,
    0x0E, 0xA6, 0x14, 0x76, 0x88, 0xBD, 0x44, 0xA1, 0x3C, 0xF6, 0x04, 0x76, 0x90, 0x78, 0xE4, 0x81,
    0x26, 0x80, 0x70, 0x0F, 0x10, 0xA7, 0xC4, 0x61, 0x95, 0x2D, 0xC6, 0x5C, 0x45, 0xCE, 0x89, 0x28,
    0x1B, 0x34, 0x1C, 0xC5, 0xE8, 0xD1, 0x64, 0xAF, 0xAC, 0xE2, 0x1C, 0x0A, 0xE2, 0xEC, 0xE7, 0x62,
    0x4C, 0xE4, 0xB4, 0x05, 0x51, 0x80, 0x93, 0x04, 0xE7, 0x8F, 0x70, 0x01, 0x6C, 0xA1, 0x62, 0x0D,
    0xFE, 0x75, 0xF8, 0xC1, 0x76, 0x3D, 0x55, 0x54, 0x5D, 0x27, 0xD1, 0xE0, 0x23, 0x13, 0x64, 0x3B,
    0x6E, 0x67, 0xCD, 0x8E, 0x28, 0x20, 0x51, 0x5A, 0x50, 0xF2, 0x45, 0x89, 0xDF, 0x2B, 0xB5, 0x78,
    0x26, 0x07, 0x17, 0x04, 0x8A, 0xE6, 0x46, 0x5F, 0x2C, 0x1D, 0x84, 0xDC, 0x24, 0xBC, 0x60, 0xD6,
    0x1D, 0x78, 0x1F, 0x25, 0xA4, 0xE5, 0x7F, 0x75, 0x5E, 0x66, 0x18, 0x97, 0x73, 0xF0, 0x01, 0xA7,
    0x84, 0x27, 0x88, 0x58, 0xA1, 0x09, 0xDE, 0xC5, 0x05, 0x09, 0x3F, 0x88, 0xA0, 0x79, 0x24, 0x54,
    0x0F, 0x80, 0xC6, 0x66, 0x07, 0xA2, 0x44, 0x2A, 0xE9, 0xA4, 0x23, 0x22, 0x3A, 0xC7, 0x36, 0x0D,
    0x0C, 0xD0, 0x28, 0x81, 0xA0, 0xB5, 0x44, 0xE9, 0xA7, 0xA0, 0xA2, 0x71, 0x52, 0x36, 0x70, 0xE8,
    0x25, 0x55, 0x9A, 0x9C, 0x46, 0xE5, 0x8F, 0x40, 0xA1, 0xB6, 0xEA, 0x6A, 0x10, 0xA3, 0x9E, 0x49,
    0x9E, 0x92, 0xA7, 0xA6, 0xCA, 0xA9, 0xA7, 0xAF, 0xE6, 0xAA, 0xEB, 0x0A, 0xA5, 0x4E, 0x99, 0x57,
    0x1D, 0xB5, 0x6E, 0x8A, 0xEA, 0x18, 0xBB, 0x16, 0x6B, 0xAC, 0x3E, 0x71, 0x20, 0xFE, 0x48, 0x16,
    0x36, 0x5D, 0x24, 0xC1, 0xA9, 0xB0, 0x69, 0xEA, 0x70, 0xEC, 0xB4, 0xC6, 0x26, 0xD9, 0x45, 0x0D,
    0x1C, 0x8C, 0x0A, 0x2C, 0x81, 0xD0, 0x76, 0x2A, 0x2D, 0xB5, 0xE0, 0xBE, 0x9A, 0xA4, 0x21, 0xB9,
    0x0C, 0x47, 0x6E, 0x9F, 0xB5, 0xDA, 0xEA, 0x28, 0xB1, 0x25, 0x88, 0x54, 0xD2, 0x98, 0x8D, 0xD5,
    0xA7, 0x09, 0x31, 0xF6, 0x25, 0x33, 0x4A, 0x48, 0x9F, 0x80, 0x34, 0xA6, 0x0A, 0x74, 0x56, 0xA1,
    0xAF, 0x0F, 0x6D, 0x10, 0x27, 0x41, 0x1B, 0x4C, 0x79, 0xA1, 0x2E, 0x5F, 0x9D, 0xAA, 0x67, 0xEF,
    0x1A, 0xD3, 0x30, 0xBC, 0xF0, 0xBD, 0xEE, 0xDE, 0xEB, 0x30, 0x57, 0xF3, 0x36, 0x4C, 0xC2, 0xBF,
    0x12, 0x5B, 0xBC, 0x6F, 0x97, 0x16, 0x9B, 0xB1, 0xB1, 0x0A, 0x59, 0xC8, 0x30, 0x9C, 0xC8, 0xDB,
    0x68, 0x9A, 0xEA, 0x02, 0x09, 0x2B, 0x70, 0x71, 0xC7, 0x15, 0xB3, 0x92, 0x71, 0xBE, 0x1A, 0x67,
    0x3C, 0xF1, 0x57, 0xF8, 0xC2, 0x6C, 0x14, 0xC4, 0xEE, 0xB2, 0x27, 0x33, 0xBC, 0x3A, 0xC3, 0x2C,
    0x2F, 0xC4, 0xEC, 0x8C, 0x25, 0xF1, 0xBB, 0xFD, 0x7E, 0x10, 0xB2, 0x12, 0xC4, 0x91, 0x5B, 0x32,
    0x54, 0x46, 0x14, 0xB7, 0xF2, 0xCC, 0x0F, 0xCF, 0x1B, 0x71, 0xC4, 0x40, 0x83, 0xF2, 0x30, 0xC6,
    0xFA, 0x92, 0x92, 0x35, 0xC3, 0x53, 0x43, 0x87, 0x5F, 0xD7, 0xA9, 0x70, 0xDD, 0xB0, 0xCE, 0x62,
    0x57, 0x6D, 0xF6, 0x98, 0x4D, 0x8B, 0x3C, 0x32, 0xD2, 0xE4, 0xA6, 0x8A, 0xB0, 0x5F, 0x4F, 0xCB,
    0x1C, 0x75, 0xCC, 0x65, 0x57, 0xBD, 0x2F, 0xD9, 0x43, 0x3B, 0xEC, 0xF5, 0xC4, 0xF9, 0x6A, 0xED,
    0x72, 0xCB, 0x36, 0xBF, 0x2C, 0xB8, 0x62, 0x7E, 0x9F, 0x2D, 0xF8, 0x08, 0x69, 0x87, 0xB1, 0xF6,
    0x3F, 0x6B, 0xAA, 0x0B, 0x9A, 0xC2, 0x7C, 0xB7, 0xFB, 0xF7, 0xE0, 0x63, 0xFE, 0xC7, 0x27, 0x35,
    0xDD, 0x18, 0xD3, 0x6D, 0x36, 0xD4, 0x72, 0x53, 0x1E, 0xF9, 0xD4, 0x1D, 0xDB, 0x1C, 0xF8, 0xE8,
    0x24, 0x2C, 0xB0, 0x44, 0x0E, 0x2C, 0x99, 0xDE, 0x6D, 0x9A, 0x90, 0xEF, 0x1C, 0x7A, 0xCB, 0x9E,
    0xBB, 0x1E, 0x35, 0xE9, 0x79, 0xCB, 0x9D, 0x39, 0xE9, 0xF0, 0x8E, 0xAD, 0x7B, 0xD8, 0x86, 0x53,
    0x0D, 0xC8, 0xBF, 0xA0, 0x73, 0x6E, 0x80, 0x12, 0x39, 0x9C, 0x27, 0x72, 0x07, 0x3A, 0xB4, 0xED,
    0x76, 0xEB, 0x5E, 0xC3, 0x44, 0xF8, 0x4D, 0xF1, 0xEE, 0x0D, 0xD8, 0xCD, 0x7A, 0xF7, 0xFD, 0xD0,
    0xEF, 0x1A, 0xE3, 0xFD, 0x12, 0xF5, 0x60, 0x07, 0xBD, 0xB3, 0xCF, 0xA2, 0xE3, 0x9D, 0xB9, 0x01,
    0xA6, 0x9F, 0x6E, 0x7C, 0x0D, 0x18, 0xE8, 0x60, 0x2D, 0xB4, 0xEC, 0x4E, 0x1E, 0x77, 0xB8, 0x81,
    0x7C, 0x9C, 0x06, 0xF1, 0x17, 0xD8, 0x60, 0x6E, 0x68, 0x03, 0x2F, 0xA0, 0x68, 0x54, 0x2A, 0x4B,
    0xFE, 0x3E, 0xFC, 0x6A, 0x90, 0x1F, 0x1A, 0xCA, 0x57, 0xBF, 0xD0, 0x98, 0x2B, 0x09, 0xF9, 0x03,
    0x80, 0x21, 0x6E, 0xD5, 0x3A, 0x00, 0x3A, 0x30, 0x0D, 0x04, 0xB4, 0x1F, 0x0E, 0x8E, 0xE0, 0x17,
    0x23, 0x48, 0xF0, 0x11, 0x67, 0x20, 0xDC, 0xF7, 0xDE, 0xF5, 0x3F, 0xF9, 0x79, 0x29, 0x52, 0x02,
    0x7C, 0x60, 0x1A, 0x70, 0x37, 0xBB, 0xB5, 0xC0, 0xEE, 0x7D, 0x21, 0x94, 0x42, 0x0A, 0x45, 0xE8,
    0xB1, 0xD8, 0xB9, 0x6E, 0x6B, 0xE0, 0x13, 0x9A, 0x0C, 0x59, 0x96, 0xB5, 0x9C, 0xD9, 0x50, 0x6C,
    0xBE, 0x3B, 0x4A, 0xE7, 0x58, 0x28, 0x0A, 0x12, 0x26, 0x06, 0x78, 0x61, 0xEB, 0x59, 0xE4, 0x7E,
    0xF8, 0xB9, 0xDD, 0xE1, 0xAC, 0x88, 0x65, 0xAB, 0x17, 0x0F, 0x03, 0x18, 0x33, 0x0D, 0xC6, 0xCE,
    0x87, 0x14, 0xAB, 0x98, 0x0D, 0xD9, 0x33, 0xC5, 0xC0, 0xD9, 0xAD, 0x55, 0x70, 0x3B, 0x5C, 0xE2,
    0x08, 0xA1, 0x27, 0xBB, 0xBC, 0x05, 0x6F, 0x73, 0xB6, 0xD3, 0x9C, 0x14, 0x61, 0x27, 0x3A, 0xC0,
    0x69, 0x11, 0x84, 0x97, 0x73, 0xA2, 0x17, 0x83, 0xB8, 0x3B, 0xAA, 0x0D, 0xF1, 0x8B, 0x50, 0x1C,
    0xE2, 0x15, 0xCF, 0xD8, 0xC3, 0x34, 0x96, 0x10, 0x86, 0x83, 0xAB, 0x21, 0x19, 0xBD, 0x37, 0x43,
    0x0E, 0xCE, 0x4E, 0x87, 0xE3, 0xA3, 0x63, 0xB8, 0x56, 0x28, 0xC8, 0x42, 0x82, 0xB0, 0x68, 0x86,
    0x4C, 0xA4, 0x22, 0x17, 0xC9, 0xC8, 0x46, 0x3A, 0xF2, 0x91, 0x90, 0x8C, 0xA4, 0x24, 0x75, 0x95,
    0x00, 0x00, 0x3B,
};

/* -------------------------------------------------------------------------
   Ethernet / IP / DHCP helpers (for DHCP probe)
   ------------------------------------------------------------------------- */

static inline uint16_t be16(const uint8_t *p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
static inline uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static inline void put_be16(uint8_t *p, uint16_t v) { p[0]=v>>8; p[1]=v&0xff; }
static inline uint16_t ip_checksum(const uint8_t *ip) {
    uint32_t s = 0;
    for (int i = 0; i < 20; i += 2) s += be16(ip + i);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return static_cast<uint16_t>(~s);
}

/* -------------------------------------------------------------------------
   TLS helpers
   ------------------------------------------------------------------------- */

bool Tunnel::ssl_writen(const void *buf, size_t n) {
    const auto *p = static_cast<const uint8_t *>(buf);
    while (n) {
        int w = SSL_write(ssl_, p, static_cast<int>(n));
        if (w <= 0) return false;
        p += w; n -= static_cast<size_t>(w);
    }
    return true;
}

bool Tunnel::ssl_readn(void *buf, size_t n) {
    auto *p = static_cast<uint8_t *>(buf);
    while (n) {
        int r = SSL_read(ssl_, p, static_cast<int>(n));
        if (r <= 0) {
            int err = SSL_get_error(ssl_, r);
            DBG("[ssl] ssl_readn failed: SSL_read=%d err=%d\n", r, err);
            return false;
        }
        p += r; n -= static_cast<size_t>(r);
    }
    return true;
}

/* -------------------------------------------------------------------------
   HTTP helpers — all requests share the same persistent TLS connection
   ------------------------------------------------------------------------- */

bool Tunnel::http_post(const char *url, const char *content_type,
                       const uint8_t *body, size_t body_len)
{
    char hdr[1024];
    int hlen = snprintf(hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Keep-Alive: timeout=15; max=19\r\n"
        "Connection: Keep-Alive\r\n"
        "\r\n",
        url, host_.c_str(), content_type, body_len);
    return ssl_writen(hdr, static_cast<size_t>(hlen))
        && ssl_writen(body, body_len);
}

std::vector<uint8_t> Tunnel::http_recv_body() {
    /* Read status line and headers byte-by-byte until \r\n\r\n */
    std::string headers;
    while (true) {
        char c;
        if (!ssl_readn(&c, 1)) {
            fprintf(stderr, "[se] http_recv_body: SSL read error after %zu header bytes\n",
                    headers.size());
            return {};
        }
        headers += c;
        if (headers.size() >= 4 &&
            headers.compare(headers.size()-4, 4, "\r\n\r\n") == 0)
            break;
        if (headers.size() > 65536) return {};
    }

    fprintf(stderr, "[se] http response headers:\n%s\n", headers.c_str());

    /* Check HTTP/1.1 200 */
    if (headers.find("HTTP/1.1 200") == std::string::npos &&
        headers.find("HTTP/1.0 200") == std::string::npos) {
        fprintf(stderr, "[se] http_recv_body: not a 200 response\n");
        return {};
    }

    /* Parse Content-Length (case-insensitive for the two common forms) */
    auto pos = headers.find("Content-Length:");
    if (pos == std::string::npos) pos = headers.find("content-length:");
    if (pos == std::string::npos) {
        fprintf(stderr, "[se] http_recv_body: no Content-Length\n");
        return {};
    }
    size_t body_len;
    try {
        body_len = static_cast<size_t>(std::stoul(headers.substr(pos + 15)));
    } catch (...) {
        fprintf(stderr, "[se] http_recv_body: bad Content-Length value\n");
        return {};
    }
    if (body_len == 0 || body_len > 16*1024*1024) {
        fprintf(stderr, "[se] http_recv_body: body_len %zu out of range\n", body_len);
        return {};
    }

    std::vector<uint8_t> body(body_len);
    if (!ssl_readn(body.data(), body_len)) {
        fprintf(stderr, "[se] http_recv_body: SSL read error reading %zu body bytes\n", body_len);
        return {};
    }
    return body;
}

bool Tunnel::pack_send(const Pack &p) {
    auto bytes = p.serialize();
    return http_post("/vpnsvc/vpn.cgi", "application/octet-stream",
                     bytes.data(), bytes.size());
}

std::optional<Pack> Tunnel::pack_recv() {
    auto body = http_recv_body();
    if (body.empty()) return std::nullopt;
    return Pack::deserialize(body.data(), body.size());
}

/* -------------------------------------------------------------------------
   Connection / handshake / auth
   ------------------------------------------------------------------------- */

bool Tunnel::connect(const std::string &host, int port,
                     bool verify_cert, const std::string &ca_path) {
    host_ = host;

    /* Resolve */
    addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0)
        return false;

    fd_ = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    bool ok = (fd_ >= 0) && (::connect(fd_, res->ai_addr, res->ai_addrlen) == 0);
    freeaddrinfo(res);
    if (!ok) return false;

    /* Disable Nagle: VPN frames must be sent immediately, not batched. */
    int one = 1;
    setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    SSL_library_init();
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) return false;

    if (verify_cert) {
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);

        /* Load CA store.  ca_path may be a directory (Android system store),
           a single PEM bundle, or empty (→ OpenSSL compiled-in defaults). */
        bool loaded = false;
        if (!ca_path.empty()) {
            struct ::stat st{};
            if (::stat(ca_path.c_str(), &st) == 0) {
                if (S_ISDIR(st.st_mode))
                    loaded = SSL_CTX_load_verify_locations(
                        ctx_, nullptr, ca_path.c_str()) == 1;
                else
                    loaded = SSL_CTX_load_verify_locations(
                        ctx_, ca_path.c_str(), nullptr) == 1;
            }
        }
        if (!loaded)
            SSL_CTX_set_default_verify_paths(ctx_);
    } else {
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    }

    ssl_ = SSL_new(ctx_);
    if (!ssl_) return false;
    SSL_set_fd(ssl_, fd_);
    SSL_set_tlsext_host_name(ssl_, host.c_str());

    if (verify_cert) {
        /* Match the cert's CN/SAN against the connect host.  Without this the
           CA validation alone is insufficient — any cert signed by any trusted
           CA for any hostname would be accepted. */
        SSL_set_hostflags(ssl_, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (SSL_set1_host(ssl_, host.c_str()) != 1) return false;
    }

    return SSL_connect(ssl_) == 1;
}

bool Tunnel::handshake() {
    /* Fixed locally-administered MAC for our virtual NIC */
    our_mac_[0]=0x02; our_mac_[1]=0xAA; our_mac_[2]=0xBB;
    our_mac_[3]=0xCC; our_mac_[4]=0xDD; our_mac_[5]=0xEE;

    /* Send watermark: POST /vpnsvc/connect.cgi, Content-Type: image/jpeg */
    if (!http_post("/vpnsvc/connect.cgi", "image/jpeg",
                   kWaterMark, sizeof(kWaterMark)))
        return false;

    /* Receive hello PACK: {hello:str, version:u32, build:u32, random:20bytes} */
    auto body = http_recv_body();
    if (body.empty()) return false;

    fprintf(stderr, "[se] handshake: body %zu bytes:\n", body.size());
    for (size_t i = 0; i < body.size(); ++i) {
        fprintf(stderr, "%02x ", body[i]);
        if ((i+1) % 16 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");

    auto p = Pack::deserialize(body.data(), body.size());
    if (!p) {
        fprintf(stderr, "[se] handshake: Pack::deserialize failed\n");
        return false;
    }

    fprintf(stderr, "[se] handshake: PACK parsed OK, hello='%s' version=%u\n",
            p->get_str("hello").c_str(), p->get_int("version"));

    auto rnd = p->get_data("random");
    fprintf(stderr, "[se] handshake: random field size=%zu\n", rnd.size());
    if (rnd.size() != 20) return false;
    memcpy(server_random_, rnd.data(), 20);
    return true;
}

bool Tunnel::authenticate(const std::string &hub,
                          const std::string &user,
                          const std::string &pass,
                          int authtype)
{
    Pack auth;
    auth.set_str("method",  "login");
    auth.set_str("hubname", hub);
    auth.set_str("username", user);
    auth.set_int("authtype", static_cast<uint32_t>(authtype));

    if (authtype == 2) {
        /* CLIENT_AUTHTYPE_PLAIN_PASSWORD: server does local hash + RADIUS fallback */
        auth.set_str("plain_password", pass);
    } else {
        /* CLIENT_AUTHTYPE_PASSWORD (1): SHA0(SHA0(pass+UPPER(user))+random) */
        std::string user_upper = user;
        for (char &c : user_upper) c = static_cast<char>(toupper(c));
        std::vector<uint8_t> hp_in;
        hp_in.insert(hp_in.end(), pass.begin(), pass.end());
        hp_in.insert(hp_in.end(), user_upper.begin(), user_upper.end());
        uint8_t hashed[20];
        se_sha0(hashed, hp_in.data(), hp_in.size());
        uint8_t sp_in[40];
        memcpy(sp_in,      hashed,         20);
        memcpy(sp_in + 20, server_random_, 20);
        uint8_t secure_pw[20];
        se_sha0(secure_pw, sp_in, 40);
        auth.set_data("secure_password", secure_pw, 20);
    }

    auth.set_str ("hello",           "SE-VPN Client");
    auth.set_int ("version",         0);
    auth.set_int ("build",           0);
    auth.set_int ("protocol",        0);   /* TCP */
    auth.set_int ("max_connection",  1);
    auth.set_bool("use_encrypt",     true);  /* keep TLS for block channel */
    auth.set_bool("use_compress",    false);
    auth.set_bool("half_connection", false);

    /* UDP acceleration negotiation: bind a UDP socket and offer it. */
    uint8_t udp_my_key[20]{}, udp_my_key_v2[128]{}, udp_init_iv[20]{};
    uint16_t udp_client_port = 0;

    int udp_fd = vpn_use_udp_accel() ? ::socket(AF_INET, SOCK_DGRAM, 0) : -1;
    if (!vpn_use_udp_accel())
        fprintf(stderr, "[udp] acceleration disabled by caller\n");
    if (udp_fd >= 0) {
        RAND_bytes(udp_my_key,    sizeof(udp_my_key));
        RAND_bytes(udp_my_key_v2, sizeof(udp_my_key_v2));
        RAND_bytes(udp_init_iv,   sizeof(udp_init_iv));

        struct sockaddr_in local{};
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = INADDR_ANY;
        local.sin_port        = 0;
        if (bind(udp_fd, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) == 0) {
            socklen_t slen = sizeof(local);
            getsockname(udp_fd, reinterpret_cast<struct sockaddr*>(&local), &slen);
            udp_client_port = ntohs(local.sin_port);

            auth.set_bool("use_udp_acceleration",         true);
            auth.set_int ("udp_acceleration_max_version", 1);
            auth.set_int ("udp_acceleration_client_ip",   0); /* server uses detected TCP src IP */
            auth.set_int ("udp_acceleration_client_port", udp_client_port);
            auth.set_data("udp_acceleration_client_key",    udp_my_key,    20);
            auth.set_data("udp_acceleration_client_key_v2", udp_my_key_v2, 128);
            fprintf(stderr, "[udp] offering accel on port %u\n", udp_client_port);
        } else {
            ::close(udp_fd); udp_fd = -1;
        }
    }

    if (!pack_send(auth)) { if (udp_fd >= 0) ::close(udp_fd); return false; }

    auto resp = pack_recv();
    if (!resp) { if (udp_fd >= 0) ::close(udp_fd); return false; }

    uint32_t err = resp->get_int("error");
    fprintf(stderr, "[auth] response error=%u\n", err);
    if (err != 0) { if (udp_fd >= 0) ::close(udp_fd); return false; }

    /* Parse UDP acceleration response from server. */
    if (udp_fd >= 0 && resp->get_int("use_udp_acceleration")) {
        uint32_t server_port   = resp->get_int("udp_acceleration_server_port");
        uint32_t server_cookie = resp->get_int("udp_acceleration_server_cookie");
        uint32_t client_cookie = resp->get_int("udp_acceleration_client_cookie");
        bool     use_enc       = resp->get_int("udp_acceleration_use_encryption") != 0;
        auto     server_key    = resp->get_data("udp_acceleration_server_key");

        fprintf(stderr, "[udp] server_port=%u enc=%d key_size=%zu\n",
                server_port, use_enc, server_key.size());

        if (server_port && server_cookie && client_cookie && server_key.size() == 20) {
            /* Use the TCP socket's remote IP as the UDP peer address. */
            struct sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            getpeername(fd_, reinterpret_cast<struct sockaddr*>(&peer), &plen);

            udp_peer_.sin_family      = AF_INET;
            udp_peer_.sin_addr        = peer.sin_addr;
            udp_peer_.sin_port        = htons(static_cast<uint16_t>(server_port));

            memcpy(udp_my_key_,   udp_my_key,        20);
            memcpy(udp_your_key_, server_key.data(),  20);
            memcpy(udp_next_iv_,  udp_init_iv,        20);

            udp_my_cookie_   = client_cookie;  /* server's YourCookie  */
            udp_your_cookie_ = server_cookie;  /* server's MyCookie    */
            udp_plain_text_  = !use_enc;
            udp_fd_          = udp_fd;
            udp_active_      = true;
            udp_ready_       = false;

            fprintf(stderr, "[udp] accel active: server_port=%u enc=%d my_cookie=%u your_cookie=%u\n",
                    server_port, use_enc, udp_my_cookie_, udp_your_cookie_);
            return true;
        }
    }

    if (udp_fd >= 0) { ::close(udp_fd); }
    return true;
}

/* -------------------------------------------------------------------------
   Tunnel packet I/O

   Cedar raw block wire format (Connection.c):
     Data batch:  uint32_BE(num_blocks) + num_blocks × [uint32_BE(size) + size bytes]
     Keepalive:   uint32_BE(0xffffffff) + uint32_BE(payload_size) + payload_size bytes
   ------------------------------------------------------------------------- */

bool Tunnel::send_frame(const uint8_t *eth, size_t len) {
    /* Build Cedar block in one contiguous buffer → single TLS record. */
    static constexpr size_t HDR = 8;
    static constexpr size_t MAX = HDR + 14 + 2048; /* 8 + max Ethernet frame */
    if (len > MAX - HDR) return false;
    uint8_t buf[MAX];
    const uint32_t one = htonl(1u);
    const uint32_t sz  = htonl(static_cast<uint32_t>(len));
    memcpy(buf,     &one, 4);
    memcpy(buf + 4, &sz,  4);
    memcpy(buf + 8, eth, len);
    std::lock_guard<std::mutex> lk(send_mutex_);
    return ssl_writen(buf, HDR + len);
}

bool Tunnel::send_keepalive() {
    uint8_t buf[8];
    const uint32_t magic = htonl(0xffffffffu);
    const uint32_t zero  = 0;
    memcpy(buf,     &magic, 4);
    memcpy(buf + 4, &zero,  4);
    std::lock_guard<std::mutex> lk(send_mutex_);
    return ssl_writen(buf, 8);
}

int Tunnel::recv_frame(uint8_t *buf, size_t buflen) {
    /* If we're mid-batch, skip the batch header and go straight to next frame. */
    if (pending_blocks_ == 0) {
        uint32_t first_net;
        if (!ssl_readn(&first_net, 4)) return -1;
        uint32_t num = ntohl(first_net);

        if (num == 0xffffffffu) {
            /* Keepalive: discard payload */
            uint32_t sz_net;
            if (!ssl_readn(&sz_net, 4)) return -1;
            uint32_t sz = ntohl(sz_net);
            if (sz > 65536) return -1;
            std::vector<uint8_t> tmp(sz);
            if (sz > 0 && !ssl_readn(tmp.data(), sz)) return -1;
            return 0;
        }

        if (num == 0) return 0;
        pending_blocks_ = num;
    }

    /* Read one frame from the current batch. */
    uint32_t sz_net;
    if (!ssl_readn(&sz_net, 4)) return -1;
    uint32_t sz = ntohl(sz_net);
    if (sz > buflen) return -1;
    if (sz > 0 && !ssl_readn(buf, sz)) return -1;
    --pending_blocks_;
    return static_cast<int>(sz);
}

/* -------------------------------------------------------------------------
   DHCP probe — discover IP assignment through the SE Ethernet tunnel
   ------------------------------------------------------------------------- */

/* Build a minimal Ethernet+IP+UDP+DHCP frame into `out`. Returns frame len. */
static size_t build_dhcp_discover(uint8_t *out, size_t bufsz,
                                  const uint8_t our_mac[6])
{
    if (bufsz < 14+20+8+300) return 0;
    memset(out, 0, 14+20+8+300);

    uint8_t *eth  = out;
    uint8_t *ip   = eth  + 14;
    uint8_t *udp  = ip   + 20;
    uint8_t *dhcp = udp  + 8;

    /* Ethernet */
    memset(eth, 0xFF, 6);                 /* dst: broadcast */
    memcpy(eth+6, our_mac, 6);            /* src: our MAC   */
    eth[12]=0x08; eth[13]=0x00;           /* ethertype IPv4 */

    /* IPv4 */
    ip[0]=0x45; ip[8]=64; ip[9]=17;       /* IHL, TTL, UDP  */
    memset(ip+12, 0x00, 4);              /* src 0.0.0.0    */
    memset(ip+16, 0xFF, 4);              /* dst 255.255.255.255 */

    /* UDP */
    put_be16(udp,   68); put_be16(udp+2, 67);  /* src=68, dst=67 */

    /* DHCP */
    dhcp[0]=1; dhcp[1]=1; dhcp[2]=6;          /* BOOTREQUEST, Ethernet, hlen=6 */
    memcpy(dhcp+28, our_mac, 6);               /* chaddr */
    dhcp[236]=99; dhcp[237]=130; dhcp[238]=83; dhcp[239]=99; /* magic cookie */
    int opt = 240;
    dhcp[opt++]=53; dhcp[opt++]=1; dhcp[opt++]=1;  /* DHCP DISCOVER */
    dhcp[opt++]=55; dhcp[opt++]=3;                  /* param request list */
    dhcp[opt++]=1; dhcp[opt++]=3; dhcp[opt++]=6;   /* subnet, router, DNS */
    dhcp[opt++]=255;                                 /* end */

    int dhcp_len = opt;
    put_be16(udp+4, static_cast<uint16_t>(8 + dhcp_len));
    put_be16(ip+2,  static_cast<uint16_t>(20 + 8 + dhcp_len));
    put_be16(ip+10, ip_checksum(ip));

    return static_cast<size_t>(14 + 20 + 8 + dhcp_len);
}

static size_t build_dhcp_request(uint8_t *out, size_t bufsz,
                                 const uint8_t our_mac[6],
                                 uint32_t offered_ip, uint32_t server_ip)
{
    if (bufsz < 14+20+8+300) return 0;
    memset(out, 0, 14+20+8+300);

    uint8_t *eth  = out;
    uint8_t *ip   = eth  + 14;
    uint8_t *udp  = ip   + 20;
    uint8_t *dhcp = udp  + 8;

    memset(eth, 0xFF, 6); memcpy(eth+6, our_mac, 6);
    eth[12]=0x08; eth[13]=0x00;
    ip[0]=0x45; ip[8]=64; ip[9]=17;
    memset(ip+12, 0, 4); memset(ip+16, 0xFF, 4);
    put_be16(udp, 68); put_be16(udp+2, 67);
    dhcp[0]=1; dhcp[1]=1; dhcp[2]=6;
    memcpy(dhcp+28, our_mac, 6);
    dhcp[236]=99; dhcp[237]=130; dhcp[238]=83; dhcp[239]=99;

    int opt = 240;
    dhcp[opt++]=53; dhcp[opt++]=1; dhcp[opt++]=3;  /* DHCP REQUEST */
    dhcp[opt++]=50; dhcp[opt++]=4;                  /* requested IP */
    dhcp[opt++]=(offered_ip>>24)&0xFF; dhcp[opt++]=(offered_ip>>16)&0xFF;
    dhcp[opt++]=(offered_ip>>8)&0xFF;  dhcp[opt++]= offered_ip&0xFF;
    dhcp[opt++]=54; dhcp[opt++]=4;                  /* server ID */
    dhcp[opt++]=(server_ip>>24)&0xFF; dhcp[opt++]=(server_ip>>16)&0xFF;
    dhcp[opt++]=(server_ip>>8)&0xFF;  dhcp[opt++]= server_ip&0xFF;
    dhcp[opt++]=255;

    int dhcp_len = opt;
    put_be16(udp+4, static_cast<uint16_t>(8 + dhcp_len));
    put_be16(ip+2,  static_cast<uint16_t>(20 + 8 + dhcp_len));
    put_be16(ip+10, ip_checksum(ip));
    return static_cast<size_t>(14 + 20 + 8 + dhcp_len);
}

void Tunnel::dhcp_send_arp_reply(const uint8_t *req, size_t len) {
    if (len < 14+28) return;
    const uint8_t *arp = req + 14;
    if (be16(arp+6) != 1) return;  /* must be ARP request */

    /* Remember gateway MAC (whoever is ARP-ing at us) */
    memcpy(gw_mac_, arp+8, 6);

    uint8_t reply[14+28];
    memcpy(reply,    req+6, 6);    /* dst = original src MAC */
    memcpy(reply+6,  our_mac_, 6); /* src = our MAC           */
    reply[12]=0x08; reply[13]=0x06;/* ethertype ARP           */
    uint8_t *a = reply + 14;
    a[0]=0; a[1]=1; a[2]=8; a[3]=0; a[4]=6; a[5]=4; /* hw Eth, proto IPv4 */
    a[6]=0; a[7]=2;               /* oper = reply            */
    memcpy(a+8,  our_mac_, 6);    /* sender MAC              */
    memcpy(a+14, arp+24, 4);      /* sender IP = target IP from request */
    memcpy(a+18, arp+8,  6);      /* target MAC = original sender MAC   */
    memcpy(a+24, arp+14, 4);      /* target IP  = original sender IP    */
    send_frame(reply, sizeof(reply));
}

std::optional<IpInfo> Tunnel::dhcp_probe(int timeout_sec) {
    static constexpr size_t MAX_ETH = 2048;

    uint8_t pkt[MAX_ETH];
    size_t  n;

    /* Cedar always sends a keepalive as the first block after StartTunnelingMode */
    send_keepalive();

    /* Send DHCP DISCOVER */
    n = build_dhcp_discover(pkt, sizeof(pkt), our_mac_);
    fprintf(stderr, "[dhcp] sending DISCOVER (%zu bytes)\n", n);
    if (!n || !send_frame(pkt, n)) { fprintf(stderr, "[dhcp] send_frame failed\n"); return std::nullopt; }
    fprintf(stderr, "[dhcp] DISCOVER sent OK\n");

    uint32_t offered_ip = 0, offered_server_ip = 0;
    bool sent_request = false;

    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::seconds(timeout_sec);

    while (Clock::now() < deadline) {
        /* Set a short SSL read timeout via SO_RCVTIMEO on the raw fd */
        struct timeval tv{ .tv_sec = 1, .tv_usec = 0 };
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int r = recv_frame(pkt, sizeof(pkt));
        fprintf(stderr, "[dhcp] recv_frame=%d\n", r);
        if (r < 0) { fprintf(stderr, "[dhcp] recv_frame error (connection lost?)\n"); return std::nullopt; }
        if (r == 0) continue;          /* keepalive */

        size_t frame_len = static_cast<size_t>(r);
        if (frame_len < 14) continue;

        uint16_t ethertype = be16(pkt + 12);
        fprintf(stderr, "[dhcp] frame len=%zu ethertype=0x%04x\n", frame_len, ethertype);

        /* Handle ARP requests from the virtual hub */
        if (ethertype == 0x0806) {
            dhcp_send_arp_reply(pkt, frame_len);
            continue;
        }

        /* Only process IPv4 */
        if (ethertype != 0x0800 || frame_len < 14+20+8+240) continue;

        const uint8_t *ip4  = pkt + 14;
        const uint8_t *udp4 = ip4 + 20;
        const uint8_t *dh   = udp4 + 8;

        if (ip4[9] != 17) continue;               /* not UDP */
        if (be16(udp4) != 67 || be16(udp4+2) != 68) continue; /* not DHCP server→client */
        if (dh[0] != 2) continue;                 /* not BOOTREPLY */
        if (dh[236]!=99||dh[237]!=130||dh[238]!=83||dh[239]!=99) continue;

        uint32_t yiaddr = be32(dh + 16);
        if (yiaddr == 0) continue;

        /* Parse DHCP options */
        uint8_t  msg_type = 0;
        uint32_t subnet   = 0xFFFFFF00u;
        uint32_t router   = 0, dns = 0, server_id = 0;
        const uint8_t *opt = dh + 240;
        const uint8_t *end = pkt + frame_len;
        while (opt < end && *opt != 255) {
            if (*opt == 0) { ++opt; continue; }
            uint8_t code = *opt++;
            if (opt >= end) break;
            uint8_t olen = *opt++;
            if (opt + olen > end) break;
            switch (code) {
                case 53: msg_type = opt[0]; break;
                case  1: if (olen>=4) subnet    = be32(opt); break;
                case  3: if (olen>=4) router    = be32(opt); break;
                case  6: if (olen>=4) dns       = be32(opt); break;
                case 54: if (olen>=4) server_id = be32(opt); break;
            }
            opt += olen;
        }

        if (msg_type == 2 && !sent_request) {
            /* OFFER → record server MAC, send REQUEST */
            memcpy(gw_mac_, pkt + 6, 6);  /* Ethernet src of OFFER = hub/DHCP MAC */
            offered_ip        = yiaddr;
            offered_server_ip = server_id;
            n = build_dhcp_request(pkt, sizeof(pkt), our_mac_,
                                   offered_ip, offered_server_ip);
            if (n) send_frame(pkt, n);
            sent_request = true;
        } else if (msg_type == 5) {
            /* ACK → update MAC in case ACK came from a different source */
            memcpy(gw_mac_, pkt + 6, 6);  /* Ethernet src of ACK */

            struct in_addr a;
            IpInfo info;
            our_ip_ = htonl(yiaddr);

            a.s_addr = htonl(yiaddr); inet_ntop(AF_INET, &a, info.ip.data(), 16);
            info.ip  = inet_ntoa(a);
            a.s_addr = htonl(router); info.gw  = inet_ntoa(a);
            a.s_addr = htonl(dns);    info.dns = inet_ntoa(a);

            /* Prefix from subnet mask */
            uint32_t m = subnet; info.prefix = 0;
            while (m & 0x80000000u) { ++info.prefix; m <<= 1; }

            memcpy(info.our_mac, our_mac_, 6);
            memcpy(info.gw_mac,  gw_mac_,  6);
            info.our_ip_net = our_ip_;

            /* gw_mac_ was captured from the DHCP sender (DHCP server MAC).
               If the router option points to a different host (e.g. a
               separate gateway box), ARP for it now so we get the right MAC.
               This is the normal "resolve next-hop MAC" step any IP stack does. */
            if (router != 0) {
                uint8_t arp_req[14+28]{};
                memset(arp_req, 0xff, 6);              /* dst = broadcast */
                memcpy(arp_req+6, our_mac_, 6);
                arp_req[12]=0x08; arp_req[13]=0x06;    /* ARP */
                uint8_t *a2 = arp_req + 14;
                a2[0]=0;a2[1]=1;a2[2]=8;a2[3]=0;a2[4]=6;a2[5]=4;
                a2[6]=0;a2[7]=1;                       /* op = request */
                memcpy(a2+8,  our_mac_, 6);            /* sender MAC */
                memcpy(a2+14, &our_ip_, 4);            /* sender IP (network byte order) */
                uint32_t gw_n = htonl(router);
                memcpy(a2+24, &gw_n, 4);               /* target IP */
                send_frame(arp_req, sizeof(arp_req));
                fprintf(stderr, "[dhcp] ARP request for gateway %s\n", info.gw.c_str());

                /* Wait up to 2 s for ARP reply from the gateway */
                auto gw_deadline = Clock::now() + std::chrono::seconds(2);
                while (Clock::now() < gw_deadline) {
                    struct timeval tv_a{ .tv_sec = 0, .tv_usec = 200000 };
                    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv_a, sizeof(tv_a));
                    int ar = recv_frame(pkt, sizeof(pkt));
                    if (ar < 14+28) continue;
                    if (be16(pkt+12) == 0x0806) { dhcp_send_arp_reply(pkt, ar); continue; }
                    const uint8_t *ra = pkt + 14;
                    if (be16(ra+6) != 2) continue;           /* not ARP reply */
                    if (be32(ra+14) != router) continue;     /* not from our gateway */
                    memcpy(gw_mac_, ra+8, 6);
                    memcpy(info.gw_mac, gw_mac_, 6);
                    fprintf(stderr, "[dhcp] gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            gw_mac_[0],gw_mac_[1],gw_mac_[2],
                            gw_mac_[3],gw_mac_[4],gw_mac_[5]);
                    break;
                }
            }

            /* Restore blocking I/O */
            struct timeval tv2{ .tv_sec = 0, .tv_usec = 0 };
            setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));

            return info;
        }
    }
    return std::nullopt;
}

/* -------------------------------------------------------------------------
   UDP acceleration I/O
   ------------------------------------------------------------------------- */

bool Tunnel::send_udp_frame(const uint8_t *eth, size_t len) {
    /* Fall back to TCP until we have confirmed bi-directional UDP. */
    if (!udp_active_ || !udp_ready_)
        return send_frame(eth, len);

    udp_now_ms_ = monotonic_ms();

    /* V1 packet layout (total = 63+len bytes):
         [IV:20] [RC4: Cookie:4 + MyTick:8 + YourTick:8 + DataSize:2 + Flag:1 + Data:N + ZeroPad:20]
       inner_size = 43+N (matches SoftEther: size variable includes IV offset). */
    const size_t inner_size = 43 + len;
    const size_t pkt_size   = 20 + inner_size;
    uint8_t pkt[20 + 43 + 14 + 2048] = {};  /* IV + inner + max Ethernet frame */
    if (pkt_size > sizeof(pkt)) return false;

    /* IV — plaintext header */
    memcpy(pkt, udp_next_iv_, 20);

    /* Build inner starting at offset 20 */
    uint8_t *p = pkt + 20;
    uint32_t cv = htonl(udp_your_cookie_);
    memcpy(p, &cv, 4); p += 4;
    wr_be64(p, udp_now_ms_);         p += 8;
    wr_be64(p, udp_last_peer_tick_); p += 8;
    uint16_t ds = htons(static_cast<uint16_t>(len));
    memcpy(p, &ds, 2); p += 2;
    *p++ = 0; /* flag: uncompressed */
    memcpy(p, eth, len);
    /* ZeroPad: already zero (vector default-initialized) */

    if (!udp_plain_text_) {
        uint8_t per_key[20];
        udp_v1_pkt_key(per_key, udp_my_key_, udp_next_iv_);
        uint8_t *inner = pkt + 20;
        rc4_crypt(inner, inner, inner_size, per_key, 20);
        /* NextIv = encrypted bytes at ZeroPad offset (inner[23+N..42+N]) */
        memcpy(udp_next_iv_, inner + 23 + len, 20);
    }

    ssize_t sent = sendto(udp_fd_, pkt, pkt_size, 0,
                          reinterpret_cast<const struct sockaddr*>(&udp_peer_),
                          sizeof(udp_peer_));
    return sent == static_cast<ssize_t>(pkt_size);
}

int Tunnel::recv_udp_frame_(uint8_t *buf, size_t buflen, int timeout_ms) {
    if (timeout_ms > 0) {
        struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        setsockopt(udp_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    uint8_t pkt[65536];
    ssize_t n = recvfrom(udp_fd_, pkt, sizeof(pkt), MSG_DONTWAIT, nullptr, nullptr);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return -1;
    }

    if (!udp_plain_text_) {
        /* Minimum: IV(20) + Cookie(4) + Ticks(16) + DataSize(2) + Flag(1) + ZeroPad(20) = 63 */
        if (n < 63) return 0;

        uint8_t *iv    = pkt;
        uint8_t *inner = pkt + 20;
        size_t   in_n  = static_cast<size_t>(n) - 20;

        uint8_t per_key[20];
        udp_v1_pkt_key(per_key, udp_your_key_, iv);
        rc4_crypt(inner, inner, in_n, per_key, 20);

        /* Verify ZeroPad (last 20 bytes must all be zero after decryption) */
        for (size_t i = in_n - 20; i < in_n; i++) {
            if (inner[i] != 0) return 0;
        }

        /* Parse decrypted inner, excluding ZeroPad */
        uint8_t *q   = inner;
        size_t   rem = in_n - 20;

        if (rem < 4) return 0;
        uint32_t cookie = ntohl(*reinterpret_cast<uint32_t*>(q)); q += 4; rem -= 4;
        if (cookie != udp_my_cookie_) return 0;

        if (rem < 8) return 0;
        /* peer_my_tick — not used by us */                       q += 8; rem -= 8;

        if (rem < 8) return 0;
        uint64_t peer_your_tick = rd_be64(q);                     q += 8; rem -= 8;
        udp_last_peer_tick_ = peer_your_tick;

        if (rem < 3) return 0;
        uint16_t data_size = ntohs(*reinterpret_cast<uint16_t*>(q)); q += 2; rem -= 2;
        /* flag */                                                    q++;    rem--;

        udp_ready_ = true; /* server is reachable via UDP */

        if (data_size == 0) return 0; /* keepalive */
        if (rem < data_size || data_size > buflen) return 0;

        memcpy(buf, q, data_size);
        return static_cast<int>(data_size);
    }

    /* Plain-text mode (no encryption) */
    if (n < 23) return 0;
    uint8_t *q = pkt;
    uint32_t cookie = ntohl(*reinterpret_cast<uint32_t*>(q)); q += 4; n -= 4;
    if (cookie != udp_my_cookie_) return 0;
    q += 8; n -= 8; /* peer_my_tick */
    udp_last_peer_tick_ = rd_be64(q); q += 8; n -= 8;
    if (n < 3) return 0;
    uint16_t data_size = ntohs(*reinterpret_cast<uint16_t*>(q)); q += 2; n -= 2;
    q++; n--; /* flag */
    udp_ready_ = true;
    if (data_size == 0 || n < data_size || data_size > (ssize_t)buflen) return 0;
    memcpy(buf, q, data_size);
    return data_size;
}

int Tunnel::recv_frame_any(uint8_t *buf, size_t buflen) {
    /* Skip poll() if we're mid-batch or SSL has buffered bytes. */
    if (pending_blocks_ > 0 || SSL_pending(ssl_) > 0)
        return recv_frame(buf, buflen);

    int tcp_fd = SSL_get_fd(ssl_);

    if (!udp_active_) {
        /* TCP-only: poll with 1 s timeout so the caller's keepalive timer fires
           even when the link is idle (without this, SSL_read blocks forever). */
        struct pollfd pfd{ tcp_fd, POLLIN, 0 };
        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) return (errno == EINTR) ? 0 : -1;
        if (ret == 0) return 0;  /* timeout — caller checks keepalive */
        if (pfd.revents & (POLLERR | POLLHUP)) return -1;
        return recv_frame(buf, buflen);
    }

    struct pollfd fds[2];
    fds[0].fd = udp_fd_;  fds[0].events = POLLIN; fds[0].revents = 0;
    fds[1].fd = tcp_fd;   fds[1].events = POLLIN; fds[1].revents = 0;

    int ret = poll(fds, 2, 1000);
    if (ret < 0) return (errno == EINTR) ? 0 : -1;
    if (ret == 0) return 0;

    if (fds[1].revents & (POLLERR | POLLHUP)) return -1;

    /* Prefer UDP for data; TCP path handles keepalives. */
    if (fds[0].revents & POLLIN) return recv_udp_frame_(buf, buflen, 0);
    if (fds[1].revents & POLLIN) return recv_frame(buf, buflen);

    return 0;
}

/* -------------------------------------------------------------------------
   Cleanup
   ------------------------------------------------------------------------- */

void Tunnel::interrupt() {
    /* Unblock SSL_read / poll() without touching SSL objects.
       Called from signal handlers or peer threads; close() must follow. */
    if (fd_ >= 0) ::shutdown(fd_, SHUT_RDWR);
    if (udp_fd_ >= 0) { ::close(udp_fd_); udp_fd_ = -1; udp_active_ = false; }
}

void Tunnel::close() {
    if (ssl_) { SSL_shutdown(ssl_); SSL_free(ssl_); ssl_ = nullptr; }
    if (ctx_) { SSL_CTX_free(ctx_); ctx_ = nullptr; }
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    if (udp_fd_ >= 0) { ::close(udp_fd_); udp_fd_ = -1; udp_active_ = false; }
    pending_blocks_ = 0;
}
