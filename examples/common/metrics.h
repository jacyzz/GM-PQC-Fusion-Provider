#pragma once
#include <stdint.h>

typedef struct {
  uint64_t start_ns;
  uint64_t end_ns;
  uint64_t bytes;
  uint64_t msgs;
} Metrics;

uint64_t now_ns(void);
void metrics_start(Metrics *m);
void metrics_add(Metrics *m, uint64_t bytes, uint64_t msgs);
void metrics_end(Metrics *m);
void metrics_print(const Metrics *m);


