/* 100% XXTEA authenticated, chunked file encryption
 * - XXTEA Merkle–Damgård construction for KDF and EtA-MAC
 * - XXTEA in CTR mode for encryption
 * - Files are encrypted in 1 MiB authenticated chunks, 16-byte MAC
 * - Headerless format, indistinguishable from random data
 * - Highly portable, no dependencies, no byte-order issues
 * Usage: $ cc -s -Os -o xxtea xxtea.c
 *        $ ./xxtea -E >file.enc message.txt
 *        $ ./xxtea -D file.enc
 * This is free and unencumbered software released into the public domain.
 */
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  include <io.h>
#  include <windows.h>
#  ifdef _MSC_VER
#    pragma comment(lib, "advapi32")
#  endif
#else
#  include <fcntl.h>
#  include <termios.h>
#  include <unistd.h>
#endif

#define COST    26       /* KDF cost (change breaks format) */
#define MAXPASS 64       /* upper limit simplifies implementation */
#define MAXBUF  (1L<<20) /* ciphertext chunk size (change breaks format) */

/* statically allocated work buffer */
static unsigned char bigbuf[MAXBUF+16];

static uint32_t
loadu32(const void *buf)
{
    /* all integers written in little endian byte order */
    const unsigned char *p = buf;
    return (uint32_t)p[0] <<  0 | (uint32_t)p[1] <<  8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void
storeu32(void *buf, uint32_t x)
{
    /* all integers written in little endian byte order */
    unsigned char *p = buf;
    p[0] = x >>  0; p[1] = x >>  8;
    p[2] = x >> 16; p[3] = x >> 24;
}

/* Encrypt 128-bit block using 128-bit key. */
static void
xxtea128_encrypt(const uint32_t k[4], uint32_t v[4])
{
    static const uint32_t t[] = {
        0x9e3779b9, 0x3c6ef372, 0xdaa66d2b, 0x78dde6e4, 0x1715609d,
        0xb54cda56, 0x5384540f, 0xf1bbcdc8, 0x8ff34781, 0x2e2ac13a,
        0xcc623af3, 0x6a99b4ac, 0x08d12e65, 0xa708a81e, 0x454021d7,
        0xe3779b90, 0x81af1549, 0x1fe68f02, 0xbe1e08bb,
    };
    for (int i = 0; i < 19; i++) {
        uint32_t e = t[i]>>2 & 3;
        v[0] += ((v[3]>>5 ^ v[1]<<2) + (v[1]>>3 ^ v[3]<<4)) ^
                ((t[i] ^ v[1]) + (k[0^e] ^ v[3]));
        v[1] += ((v[0]>>5 ^ v[2]<<2) + (v[2]>>3 ^ v[0]<<4)) ^
                ((t[i] ^ v[2]) + (k[1^e] ^ v[0]));
        v[2] += ((v[1]>>5 ^ v[3]<<2) + (v[3]>>3 ^ v[1]<<4)) ^
                ((t[i] ^ v[3]) + (k[2^e] ^ v[1]));
        v[3] += ((v[2]>>5 ^ v[0]<<2) + (v[0]>>3 ^ v[2]<<4)) ^
                ((t[i] ^ v[0]) + (k[3^e] ^ v[2]));
    }
}

static void
xxtea128_hash_init(uint32_t ctx[4])
{
    /* first 32 hexadecimal digits of pi */
    ctx[0] = 0x243f6a88; ctx[1] = 0x85a308d3;
    ctx[2] = 0x13198a2e; ctx[3] = 0x03707344;
}

/* Mix one block into the hash state. */
static void
xxtea128_hash_update(uint32_t ctx[4], const uint32_t block[4])
{
    /* Merkle–Damgård construction using XXTEA */
    xxtea128_encrypt(block, ctx);
}

/* Append raw bytes to the hash state.
 * - len must be a multiple of 16.
 */
static void
xxtea128_hash_append(uint32_t ctx[4], const void *buf, size_t len)
{
    assert(len % 16 == 0);
    uint32_t block[4];
    for (const char *p = buf; len >= 16; len -= 16, p += 16) {
        block[0] = loadu32(p +  0); block[1] = loadu32(p +  4);
        block[2] = loadu32(p +  8); block[3] = loadu32(p + 12);
        xxtea128_hash_update(ctx, block);
    }
}

/* Append final raw-byte block to hash state.
 * - len must be less than 16
 */
static void
xxtea128_hash_final(uint32_t ctx[4], const void *buf, size_t len)
{
    assert(len < 16);
    char tmp[16];
    memset(tmp, 16-len, 16);
    memcpy(tmp, buf, len);
    uint32_t block[4] = {
        loadu32(tmp +  0), loadu32(tmp +  4),
        loadu32(tmp +  8), loadu32(tmp + 12),
    };
    /* Davies–Meyer for last block to break length-extension attacks and
     * prevent using the decryption function to roll it backwards
     */
    uint32_t pre[4] = {ctx[0], ctx[1], ctx[2], ctx[3]};
    xxtea128_encrypt(block, ctx);
    ctx[0] ^= pre[0]; ctx[1] ^= pre[1];
    ctx[2] ^= pre[2]; ctx[3] ^= pre[3];
}

/* Derive a 128-bit key from a password and 128-bit salt.
 *
 * The password is concatenated, including null terminator, repeatedly
 * until 2^cost bytes, then fed into the hash. The salt is fed into the
 * hash first.
 *
 * - password must be less than MAXPASS bytes (implementation limit)
 * - cost must be > 10 and < 64
 */
static void
kdf(uint32_t key[4], const char *password, const uint32_t salt[4], int cost)
{
    assert(cost > 10 && cost < 64);
    assert(strlen(password) < MAXPASS);

    /* precompute all block arrangements */
    int len = strlen(password) + 1;
    volatile char block[16*16*MAXPASS];
    /* note: iteration count independent of password length */
    for (int i = 0; i < (int)sizeof(block); i++) {
        block[i] = password[i%len];
    }

    xxtea128_hash_init(key);
    xxtea128_hash_update(key, salt);
    for (long long i = 0; i < 1LL<<cost; i += 16) {
        xxtea128_hash_append(key, (char *)block + i%len, 16);
    }
    xxtea128_hash_final(key, 0, 0);

    /* wipe password-filled workspace (best effort) */
    for (int i = 0; i < (int)sizeof(block); i++) {
        block[i] = 0;
    }
}

static void
increment(uint32_t ctr[4])
{
    /* 128-bit increment, first word changes fastest */
    if (!++ctr[0]) if (!++ctr[1]) if (!++ctr[2]) ++ctr[3];
}

/* Fill buf with system entropy. */
static int fillrand(void *buf, int len);

/* Display prompt then read zero-terminated, UTF-8 password.
 * Return password length with terminator, zero on input error, negative if
 * the buffer was too small.
 */
static int read_password(char *buf, int len, char *prompt);

#ifdef _WIN32
static int
fillrand(void *buf, int len)
{
    BOOLEAN NTAPI SystemFunction036(PVOID, ULONG);
    return !SystemFunction036(buf, len);
}

static int
read_password(char *buf, int len, char *prompt)
{
    /* Ref: https://nullprogram.com/blog/2020/05/04/ */

    /* Resources that will be cleaned up */
    int pwlen = 0;
    DWORD orig = 0;
    WCHAR *wbuf = 0;
    SIZE_T wbuf_len = 0;
    HANDLE hi, ho = INVALID_HANDLE_VALUE;

    /* Set up input console handle */
    DWORD access = GENERIC_READ | GENERIC_WRITE;
    hi = CreateFileA("CONIN$", access, 0, 0, OPEN_EXISTING, 0, 0);
    if (!GetConsoleMode(hi, &orig)) goto done;
    DWORD mode = orig;
    mode |= ENABLE_PROCESSED_INPUT;
    mode |= ENABLE_LINE_INPUT;
    mode &= ~ENABLE_ECHO_INPUT;
    if (!SetConsoleMode(hi, mode)) goto done;

    /* Set up output console handle */
    ho = CreateFileA("CONOUT$", GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (!WriteConsoleA(ho, prompt, strlen(prompt), 0, 0)) goto done;

    /* Allocate a wide character buffer the size of the output */
    wbuf_len = (len - 1 + 2) * sizeof(WCHAR);
    wbuf = HeapAlloc(GetProcessHeap(), 0, wbuf_len);
    if (!wbuf) goto done;

    /* Read and convert to UTF-8 */
    DWORD nread;
    if (!ReadConsoleW(hi, wbuf, len - 1 + 2, &nread, 0)) goto done;
    if (nread < 2) goto done;
    if (wbuf[nread-2] != '\r' || wbuf[nread-1] != '\n') {
        pwlen = -1;
        goto done;
    }
    wbuf[nread-2] = 0;  /* truncate "\r\n" */
    pwlen = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, len, 0, 0);

done:
    if (wbuf) {
        SecureZeroMemory(wbuf, wbuf_len);
        HeapFree(GetProcessHeap(), 0, wbuf);
    }
    /* Exploit that operations on INVALID_HANDLE_VALUE are no-ops */
    WriteConsoleA(ho, "\n", 1, 0, 0);
    SetConsoleMode(hi, orig);
    CloseHandle(ho);
    CloseHandle(hi);
    return pwlen;
}

#else /* ! _WIN32 */
static int
fillrand(void *buf, int len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 1;
    int r = !fread(buf, len, 1, f);
    fclose(f);
    return r;
}

static int
read_password(char *buf, int len, char *prompt)
{
    int r = 0;
    struct termios old, new;
    int tty = open("/dev/tty", O_RDWR);
    if (tty) {
        tcgetattr(tty, &old);
        write(tty, prompt, strlen(prompt));
        new = old;
        new.c_lflag &= ~ECHO;
        tcsetattr(tty, TCSANOW, &new);
        r = read(tty, buf, len);
        if (r < 0) {
            r = 0;
        } else if (r > 0 && buf[r-1] != '\n') {
            /* consume the rest of the line */
            do {
                r = read(tty, buf, len);
            } while (r > 0 && buf[r-1] != '\n');
            memset(buf, 0, len);
            r = -1;
        } else if (r > 0) {
            buf[r-1] = 0;
        }
    }
    write(tty, "\n", 1);
    tcsetattr(tty, TCSANOW, &old);
    close(tty);
    return r;
}
#endif

enum error {ERR_OK, ERR_ENT, ERR_READ, ERR_WRITE, ERR_TRUNC, ERR_INVALID};
static const char *errmsg[] = {
    [ERR_ENT] = "failed to gather entropy",
    [ERR_READ] = "input error",
    [ERR_WRITE] = "output error",
    [ERR_TRUNC] = "input is truncated",
    [ERR_INVALID] = "wrong password / bad input",
};

static enum error
fencrypt(FILE *in, FILE *out, const char *password)
{
    enum error err = ERR_OK;
    uint32_t ctr[4];
    volatile uint32_t key[4];

    if (fillrand(ctr, sizeof(ctr))) {
        return ERR_ENT;
    }

    /* first 16 bytes of the file is the IV */
    storeu32(bigbuf +  0, ctr[0]);
    storeu32(bigbuf +  4, ctr[1]);
    storeu32(bigbuf +  8, ctr[2]);
    storeu32(bigbuf + 12, ctr[3]);
    if (!fwrite(bigbuf, 16, 1, out)) {
        return ERR_WRITE;
    }

    /* IV is also the salt */
    kdf((uint32_t *)key, password, ctr, COST);

    for (;;) {
        size_t n = fread(bigbuf, 1, MAXBUF, in);
        if (!n && ferror(in)) {
            err = ERR_READ;
            break;
        }
        /* note: zero-length chunk is fine */

        /* MAC is hash(key || counter || ct)
         * Counter is under hostile control, so append after the key. It's
         * also different for each chunk, so chunks must appear in order.
         */
        uint32_t mac[4];
        xxtea128_hash_init(mac);
        xxtea128_hash_update(mac, (uint32_t *)key);
        xxtea128_hash_update(mac, ctr);

        for (size_t i = 0; i < (n + 15)/16; i++) {
            uint32_t b[4] = {ctr[0], ctr[1], ctr[2], ctr[3]};
            increment(ctr);
            xxtea128_encrypt((uint32_t *)key, b);
            b[0] ^= loadu32(bigbuf + i*16 +  0);
            b[1] ^= loadu32(bigbuf + i*16 +  4);
            b[2] ^= loadu32(bigbuf + i*16 +  8);
            b[3] ^= loadu32(bigbuf + i*16 + 12);
            storeu32(bigbuf + i*16 +  0, b[0]);
            storeu32(bigbuf + i*16 +  4, b[1]);
            storeu32(bigbuf + i*16 +  8, b[2]);
            storeu32(bigbuf + i*16 + 12, b[3]);
        }

        /* MAC appended to ciphertext */
        xxtea128_hash_append(mac, bigbuf, n/16*16);
        xxtea128_hash_final(mac, bigbuf + n/16*16, n%16);
        storeu32(bigbuf + n +  0, mac[0]);
        storeu32(bigbuf + n +  4, mac[1]);
        storeu32(bigbuf + n +  8, mac[2]);
        storeu32(bigbuf + n + 12, mac[3]);
        if (!fwrite(bigbuf, n+16, 1, out)) {
            err = ERR_WRITE;
            break;
        }

        /* short chunk indicates end of input */
        if (n < MAXBUF) {
            err = fflush(out) ? ERR_WRITE : ERR_OK;
            break;
        }
    }

    /* wipe the key via volatile (best effort) */
    key[0] = key[1] = key[2] = key[3] = 0;
    return err;
}

static enum error
fdecrypt(FILE *in, FILE *out, const char *password)
{
    enum error err = ERR_OK;
    uint32_t ctr[4];
    volatile uint32_t key[4];

    /* first 16 bytes of the file is the IV */
    if (!fread(bigbuf, 16, 1, in)) {
        return ferror(in) ? ERR_READ : ERR_TRUNC;
    }
    ctr[0] = loadu32(bigbuf +  0);
    ctr[1] = loadu32(bigbuf +  4);
    ctr[2] = loadu32(bigbuf +  8);
    ctr[3] = loadu32(bigbuf + 12);

    /* IV is also the salt */
    kdf((uint32_t *)key, password, ctr, COST);

    for (;;) {
        size_t n = fread(bigbuf, 1, MAXBUF+16, in);
        if (!n && ferror(in)) {
            err = ERR_READ;
            break;
        }
        if (n < 16) {
            err = ERR_TRUNC;
            break;
        }
        n -= 16; /* chop off MAC */

        /* check MAC before decryption (doom principle) */
        uint32_t mac[4];
        xxtea128_hash_init(mac);
        xxtea128_hash_update(mac, (uint32_t *)key);
        xxtea128_hash_update(mac, ctr);
        xxtea128_hash_append(mac, bigbuf, + n/16*16);
        xxtea128_hash_final(mac, bigbuf + n/16*16, n%16);
        char macbuf[16];
        storeu32(macbuf +  0, mac[0]);
        storeu32(macbuf +  4, mac[1]);
        storeu32(macbuf +  8, mac[2]);
        storeu32(macbuf + 12, mac[3]);
        /* note: constant-time comparison unnecessary here */
        if (memcmp(bigbuf + n, macbuf, 16)) {
            err = ERR_INVALID;
            break;
        }

        for (size_t i = 0; i < (n + 15)/16; i++) {
            uint32_t b[4] = {ctr[0], ctr[1], ctr[2], ctr[3]};
            increment(ctr);
            xxtea128_encrypt((uint32_t *)key, b);
            b[0] ^= loadu32(bigbuf + i*16 +  0);
            b[1] ^= loadu32(bigbuf + i*16 +  4);
            b[2] ^= loadu32(bigbuf + i*16 +  8);
            b[3] ^= loadu32(bigbuf + i*16 + 12);
            storeu32(bigbuf + i*16 +  0, b[0]);
            storeu32(bigbuf + i*16 +  4, b[1]);
            storeu32(bigbuf + i*16 +  8, b[2]);
            storeu32(bigbuf + i*16 + 12, b[3]);
        }
        if (n && !fwrite(bigbuf, n, 1, out)) {
            err = ERR_WRITE;
            break;
        }

        /* short chunk indicates end of input */
        if (n < MAXBUF) {
            err = fflush(out) ? ERR_WRITE : ERR_OK;
            break;
        }
    }

    /* wipe the key via volatile (best effort) */
    key[0] = key[1] = key[2] = key[3] = 0;
    return err;
}

static int xoptind = 1;
static int xopterr = 1;
static int xoptopt;
static char *xoptarg;

static int
xgetopt(int argc, char * const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    /* reset? */
    if (xoptind == 0) {
        xoptind = 1;
        optpos = 1;
    }

    arg = argv[xoptind];
    if (arg && strcmp(arg, "--") == 0) {
        xoptind++;
        return -1;
    } else if (!arg || arg[0] != '-' || !isalnum(arg[1])) {
        return -1;
    } else {
        const char *opt = strchr(optstring, arg[optpos]);
        xoptopt = arg[optpos];
        if (!opt) {
            if (xopterr && *optstring != ':')
                fprintf(stderr, "%s: illegal option: %c\n", argv[0], xoptopt);
            return '?';
        } else if (opt[1] == ':') {
            if (arg[optpos + 1]) {
                xoptarg = (char *)arg + optpos + 1;
                xoptind++;
                optpos = 1;
                return xoptopt;
            } else if (argv[xoptind + 1]) {
                xoptarg = (char *)argv[xoptind + 1];
                xoptind += 2;
                optpos = 1;
                return xoptopt;
            } else {
                if (xopterr && *optstring != ':')
                    fprintf(stderr, "%s: option requires an argument: %c\n",
                            argv[0], xoptopt);
                return *optstring == ':' ? ':' : '?';
            }
        } else {
            if (!arg[++optpos]) {
                xoptind++;
                optpos = 1;
            }
            return xoptopt;
        }
    }
}

static void
usage(FILE *f)
{
    fputs("usage: xxtea <-E|-D> [-h] [-o FILE] [-p PASSWORD] [FILE]\n", f);
}

int
main(int argc, char *argv[])
{
    enum {MODE_NONE, MODE_ENCRYPT, MODE_DECRYPT} mode = MODE_NONE;
    const char *outfile = 0;
    const char *infile = 0;
    char *password = 0;
    enum error err;

    #ifdef _WIN32
    /* Set stdin/stdout to binary mode. */
    _setmode(0, 0x8000);
    _setmode(1, 0x8000);
    #endif

    int option;
    while ((option = xgetopt(argc, argv, "DEho:p:")) != -1) {
        switch (option) {
        case 'D': mode = MODE_DECRYPT; break;
        case 'E': mode = MODE_ENCRYPT; break;
        case 'h': usage(stdout); return 0;
        case 'o': outfile = xoptarg; break;
        case 'p': password = xoptarg; break;
        default: usage(stderr); return 1;
        }
    }

    if (mode == MODE_NONE) {
        usage(stderr);
        return 1;
    }

    static char buf[2][MAXPASS];  /* static -> not on stack */
    if (!password) {
        password = buf[0];
        int r = read_password(buf[0], sizeof(buf[0]), "password: ");
        if (r == 0) {
            fputs("xxtea: failed to read password\n", stderr);
            return 1;
        }
        if (r < 0) {
            fprintf(stderr, "xxtea: password must be < %d bytes\n", MAXPASS);
            return 1;
        }
        if (mode == MODE_ENCRYPT) {
            r = read_password(buf[1], sizeof(buf[1]), "password (repeat): ");
            if (r == 0) {
                fputs("xxtea: failed to read password\n", stderr);
                return 1;
            }
            if (r < 0 || strcmp(buf[0], buf[1])) {
                fputs("xxtea: passwords don't match\n", stderr);
                return 1;
            }
        }
    }

    if (argv[xoptind] && argv[xoptind+1]) {
        usage(stderr);
        return 1;
    }
    infile = argv[xoptind];

    FILE *in = !infile || !strcmp(infile, "-") ? stdin : fopen(infile, "rb");
    if (!in) {
        fprintf(stderr, "xxtea: could not open input file: %s\n", infile);
        return 1;
    }
    FILE *out = !outfile ? stdout : fopen(outfile, "wb");
    if (!out) {
        fprintf(stderr, "xxtea: could not open output file: %s\n", outfile);
        return 1;
    }

    switch (mode) {
    case MODE_ENCRYPT: err = fencrypt(in, out, password); break;
    case MODE_DECRYPT: err = fdecrypt(in, out, password); break;
    default: return 1;
    }
    if (outfile) {
        fclose(out); /* error already checked by fflush(3) */
    }
    if (infile) {
        fclose(in);
    }

    if (err) {
        fprintf(stderr, "xxtea: %s\n", errmsg[err]);
        if (outfile) {
            remove(outfile);
        }
        return 1;
    }
    return 0;
}
