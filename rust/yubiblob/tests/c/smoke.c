/* SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
 *
 * SPDX-License-Identifier: MIT
 *
 * libyubiblob from C (spec 0039): built against yubiblob.h, linked with
 * libyubiblob, run on a YubiKey (simulated by scripts/check-libyubiblob,
 * or real).  Stores a blob, lists, fetches, tries a wrong PIN, removes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yubiblob.h"

#define CHECK(call)                                                              \
    do {                                                                         \
        yubiblob_status_t status_ = (call);                                      \
        if (status_ != YUBIBLOB_OK) {                                            \
            fprintf(stderr, "%s: status %d: %s\n", #call, (int)status_,          \
                    yubiblob_last_error());                                      \
            return 1;                                                            \
        }                                                                        \
    } while (0)

#define EXPECT(cond)                                                             \
    do {                                                                         \
        if (!(cond)) {                                                           \
            fprintf(stderr, "failed: %s\n", #cond);                              \
            return 1;                                                            \
        }                                                                        \
    } while (0)

static void count_touch(void* user)
{
    ++*(int*)user;
}

int main(int argc, char** argv)
{
    const char* pin = argc > 1 ? argv[1] : "654321";
    const uint8_t* p = (const uint8_t*)pin;
    size_t pin_len = strlen(pin);
    const char content[] = "hello from C";

    EXPECT(yubiblob_abi_version() == YUBIBLOB_ABI_VERSION);
    printf("libyubiblob %s\n", yubiblob_version());

    yubiblob_session_t* s = NULL;
    CHECK(yubiblob_open(0, 0, &s));

    yubiblob_store_info_t room;
    CHECK(yubiblob_store_info(s, &room));
    EXPECT(room.kind == YUBIBLOB_KIND_LEGACY);
    int touches = 0;
    yubiblob_touch_callback_t callback = count_touch;
    CHECK(yubiblob_set_touch_callback(s, callback, &touches));

    CHECK(yubiblob_store(s, "smoke-test", (const uint8_t*)content, sizeof content,
                         YUBIBLOB_STORE_ENCRYPT | YUBIBLOB_STORE_COMPRESS, p, pin_len));

    yubiblob_blob_info_t* blobs = NULL;
    size_t count = 0;
    CHECK(yubiblob_list(s, &blobs, &count));
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(blobs[i].name, "smoke-test") == 0) {
            found = 1;
            EXPECT(blobs[i].encrypted);
            EXPECT(blobs[i].size == sizeof content);
            EXPECT(blobs[i].signature == YUBIBLOB_SIGNATURE_VERIFIED);
        }
    }
    yubiblob_blobs_free(blobs, count);
    EXPECT(found);

    uint8_t* data = NULL;
    size_t len = 0;
    CHECK(yubiblob_fetch(s, "smoke-test", p, pin_len, &data, &len));
    EXPECT(len == sizeof content && memcmp(data, content, len) == 0);
    yubiblob_buffer_free(data, len);

    /* A wrong PIN, then the right one (which resets the counter). */
    EXPECT(yubiblob_fetch(s, "smoke-test", (const uint8_t*)"000000", 6, &data, &len)
           == YUBIBLOB_ERR_WRONG_PIN);
    EXPECT(yubiblob_last_pin_tries() >= 0);
    CHECK(yubiblob_fetch(s, "smoke-test", p, pin_len, &data, &len));
    yubiblob_buffer_free(data, len);

    CHECK(yubiblob_remove(s, "smoke-test", 0, p, pin_len));
    EXPECT(touches == 0); /* a legacy store asks for no touch */
    EXPECT(yubiblob_fetch(s, "smoke-test", p, pin_len, &data, &len) == YUBIBLOB_ERR_NOT_FOUND);

    yubiblob_close(s);
    printf("libyubiblob from C: ok\n");
    return 0;
}
