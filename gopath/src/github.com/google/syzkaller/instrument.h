#ifndef S2E_INSTRUMENT_H
#define S2E_INSTRUMENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum INTRUMENT_COMMANDS {
    INSTRUMENT_QUERY,
    INSTRUMENT_ECHO
};

struct INSTRUMENT_ECHO {
    uint64_t type;
    unsigned size;
} __attribute((packed));

struct INSTRUMENT_QUERY {
    uint8_t type;
    unsigned size;
} __attribute__((packed));

struct INTRUMENT_COMMAND {
    enum INTRUMENT_COMMANDS Command;
    union {
        struct INSTRUMENT_ECHO echo;
        struct INSTRUMENT_QUERY query;
    };
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif