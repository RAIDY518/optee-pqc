#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "bench.h"

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

uint64_t diff_ns(const struct timespec *s, const struct timespec *e)
{
	return (uint64_t)(e->tv_sec - s->tv_sec) * 1000000000ULL +
	       (uint64_t)(e->tv_nsec - s->tv_nsec);
}

void print_stats(uint64_t *arr, size_t n, const char *tag)
{
	uint64_t min = arr[0], max = arr[0];
	__uint128_t sum = 0;

	for (size_t i = 0; i < n; i++) {
		if (arr[i] < min) min = arr[i];
		if (arr[i] > max) max = arr[i];
		sum += arr[i];
	}

	qsort(arr, n, sizeof(arr[0]), cmp_u64);

	uint64_t p50 = arr[(size_t)(0.50 * (n - 1))];
	uint64_t p95 = arr[(size_t)(0.95 * (n - 1))];
	uint64_t p99 = arr[(size_t)(0.99 * (n - 1))];
	double   avg = (double)sum / (double)n;

	printf("[%s] n=%zu\n", tag, n);
	printf("  min   = %" PRIu64 " ns\n", min);
	printf("  avg   = %.2f ns\n", avg);
	printf("  p50   = %" PRIu64 " ns\n", p50);
	printf("  p95   = %" PRIu64 " ns\n", p95);
	printf("  p99   = %" PRIu64 " ns\n", p99);
	printf("  max   = %" PRIu64 " ns\n", max);
}
