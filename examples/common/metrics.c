#include "metrics.h"
#include <stdio.h>
#include <time.h>

uint64_t now_ns(void) {
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

void metrics_start(Metrics *m) { m->start_ns = now_ns(); m->bytes = m->msgs = 0; }
void metrics_add(Metrics *m, uint64_t bytes, uint64_t msgs) { m->bytes += bytes; m->msgs += msgs; }
void metrics_end(Metrics *m) { m->end_ns = now_ns(); }

void metrics_print(const Metrics *m) {
  double sec = (double)(m->end_ns - m->start_ns) / 1e9;
  double mbps = sec > 0 ? (m->bytes / (1024.0*1024.0)) / sec : 0.0;
  double mps = sec > 0 ? (m->msgs / sec) : 0.0;
  printf("duration=%.3fs bytes=%llu msgs=%llu throughput=%.2f MiB/s msgps=%.0f\n",
         sec, (unsigned long long)m->bytes, (unsigned long long)m->msgs, mbps, mps);
}


