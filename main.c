#include <libgen.h>
#include <iot/mongoose.h>
#include "finder.h"


static void usage(char *prog) {
    fprintf(stderr,
            "IoT-SDK v.%s\n"
            "Usage: %s OPTIONS\n"
            "  -n SERVICE  - service name for different product, default: '%s'\n"
            "  -p PORT     - udp broadcast port, default: '%s'\n"
            "  -x PATH     - finder callback lua script, default: '%s'\n"
            "  -d DATA     - finder broadcast default data, defualt: NULL\n"
            "  -s SIGN     - enable/disable check sign, 1: enable, 0: disable, defualt: %d\n"
            "  -k KEY      - udp data sign key, defualt: '******'\n"
            "  -t TIME     - time in seconds to broadcast, defualt: %d\n"
            "  -c COUNT    - udp broadcast request every time, defualt: %d\n"
            "  -v LEVEL    - debug level, from 0 to 4, default: %d\n"
            "\n"
            "  kill -USR1 `pidof %s` resend broadcast data\n"
            "\n"
            "  kill -USR2 `pidof %s` stop broadcast data\n"
            "\n",
            MG_VERSION, prog, "iot-device", "5858", "/www/iot/handler/iot-finder.lua", 1, 60, 1, MG_LL_INFO, basename(prog), basename(prog));

    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {

    struct finder_option opts = {
        .service = "iot-device",
        .broadcast_port = "5858",
        .callback_lua = "/www/iot/handler/iot-finder.lua",
        .payload = NULL,
        .time = 60,
        .sign = 1,
        .key = "1a2b3C4D5e6f",
        .count = 1,
        .debug_level = MG_LL_INFO
    };

    // Parse command-line flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0) {
            opts.service = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0) {
            opts.broadcast_port = argv[++i];
        } else if (strcmp(argv[i], "-x") == 0) {
            opts.callback_lua = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0) {
            opts.payload = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0) {
            opts.sign = atoi(argv[++i]);
        }  else if (strcmp(argv[i], "-k") == 0) {
            opts.key = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0) {
            opts.time = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-c") == 0) {
            opts.count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            opts.debug_level = atoi(argv[++i]);
        } else {
            usage(argv[0]);
        }
    }

    if (opts.count < 1 || opts.time < 3) {
        usage(argv[0]);
    }

    MG_INFO(("IoT-SDK version  : v%s", MG_VERSION));
    MG_INFO(("udp broadcast to : %s", opts.broadcast_port));
    MG_INFO(("callback lua     : %s", opts.callback_lua));

    finder_main(&opts);
    return 0;
}