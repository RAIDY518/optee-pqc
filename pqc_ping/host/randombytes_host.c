/* Normal-world randombytes using getrandom(2).
 * This replaces ta/pqclean/common/randombytes.c (which uses TEE_GenerateRandom)
 * when the ML-KEM encaps function is compiled into the host binary. */
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>
#include <sys/types.h>

void randombytes(uint8_t *out, size_t outlen)
{
	while (outlen > 0) {
		ssize_t r = getrandom(out, outlen, 0);
		if (r > 0) {
			out    += r;
			outlen -= (size_t)r;
		}
	}
}
