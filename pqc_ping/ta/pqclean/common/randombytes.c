#include <tee_internal_api.h>
#include <stdint.h>
#include <stddef.h>

void randombytes(uint8_t *out, size_t outlen)
{
    TEE_GenerateRandom(out, outlen);
}
