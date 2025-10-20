#include <stdlib.h>
#include "../include/hybrid_common.h"

void free_key_data(uint8_t *key_data) {
    if (key_data) {
        free(key_data);
    }
}


