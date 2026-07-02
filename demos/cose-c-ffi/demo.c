// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "tav/cose.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Buffer {
    uint8_t *data;
    size_t len;
} Buffer;

static void free_buffer(Buffer *buffer) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0;
}

static int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static Buffer decode_hex(const char *hex) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "hex input must contain an even number of digits\n");
        exit(1);
    }

    Buffer buffer = {
        .data = malloc(hex_len / 2),
        .len = hex_len / 2,
    };
    if (buffer.data == NULL && buffer.len != 0) {
        perror("malloc");
        exit(1);
    }

    for (size_t i = 0; i < buffer.len; i++) {
        int high = hex_nibble(hex[i * 2]);
        int low = hex_nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0) {
            fprintf(stderr, "hex input contains a non-hex character at byte offset %zu\n", i);
            free_buffer(&buffer);
            exit(1);
        }
        buffer.data[i] = (uint8_t)((high << 4) | low);
    }

    return buffer;
}

static void check_cose_error(TavError *error, const char *context) {
    if (error == NULL) {
        return;
    }

    TavErrorCode code = tav_error_code(error);
    fprintf(stderr, "%s: %s\n", context, tav_error_message(error));
    tav_error_free(error);
    exit(code == TAV_ERROR_OK ? 1 : (int)code);
}

static void print_indent(size_t indent) {
    for (size_t i = 0; i < indent; i++) {
        printf("  ");
    }
}

static void print_hex_bytes(const uint8_t *data, size_t len) {
    printf("h'");
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("'");
}

static void print_escaped_text(const char *text, size_t len) {
    printf("\"");
    for (size_t i = 0; i < len; i++) {
        uint8_t ch = (uint8_t)text[i];
        switch (ch) {
            case '\\':
                printf("\\\\");
                break;
            case '"':
                printf("\\\"");
                break;
            case '\n':
                printf("\\n");
                break;
            case '\r':
                printf("\\r");
                break;
            case '\t':
                printf("\\t");
                break;
            default:
                if (ch >= 0x20 && ch <= 0x7e) {
                    putchar(ch);
                } else {
                    printf("\\x%02x", (unsigned int)ch);
                }
                break;
        }
    }
    printf("\"");
}

static void print_cbor_value(const TavCborValue *value, size_t indent);

static void print_protected_header(const TavCborValue *value, size_t indent) {
    const uint8_t *data = NULL;
    size_t len = 0;
    check_cose_error(tav_cbor_value_bytes(value, &data, &len), "read protected header bytes");

    print_indent(indent);
    printf("protected_header\n");

    if (len == 0) {
        print_indent(indent + 1);
        printf("map(len=0)\n");
        return;
    }

    TavCborValue *protected_header = NULL;
    check_cose_error(
        tav_cbor_value_from_bytes(data, len, &protected_header),
        "parse protected header");
    print_cbor_value(protected_header, indent + 1);
    tav_cbor_value_free(protected_header);
}

static void print_array(const TavCborValue *value, size_t indent) {
    size_t len = 0;
    check_cose_error(tav_cbor_value_len(value, &len), "read array length");

    print_indent(indent);
    printf("array(len=%zu)\n", len);
    for (size_t i = 0; i < len; i++) {
        const TavCborValue *child = NULL;
        check_cose_error(tav_cbor_value_array_at(value, i, &child), "read array child");
        print_indent(indent + 1);
        printf("[%zu]\n", i);
        print_cbor_value(child, indent + 2);
    }
}

static void print_cose_sign1(const TavCborValue *value, size_t indent) {
    size_t len = 0;
    check_cose_error(tav_cbor_value_len(value, &len), "read COSE_Sign1 length");

    print_indent(indent);
    printf("array(len=%zu)\n", len);
    for (size_t i = 0; i < len; i++) {
        const TavCborValue *child = NULL;
        check_cose_error(tav_cbor_value_array_at(value, i, &child), "read COSE_Sign1 field");
        print_indent(indent + 1);
        printf("[%zu]\n", i);
        print_cbor_value(child, indent + 2);
        if (i == TAV_COSE_SIGN1_PROTECTED) {
            print_protected_header(child, indent + 2);
        }
    }
}

static void print_map(const TavCborValue *value, size_t indent) {
    size_t len = 0;
    check_cose_error(tav_cbor_value_len(value, &len), "read map length");

    print_indent(indent);
    printf("map(len=%zu)\n", len);
    for (size_t i = 0; i < len; i++) {
        const TavCborValue *key = NULL;
        const TavCborValue *child = NULL;
        check_cose_error(tav_cbor_value_map_entry_at(value, i, &key, &child), "read map entry");

        print_indent(indent + 1);
        printf("entry[%zu].key\n", i);
        print_cbor_value(key, indent + 2);
        print_indent(indent + 1);
        printf("entry[%zu].value\n", i);
        print_cbor_value(child, indent + 2);
    }
}

static void print_cbor_value(const TavCborValue *value, size_t indent) {
    switch (tav_cbor_value_kind(value)) {
        case TAV_CBOR_KIND_INT: {
            int64_t v = 0;
            check_cose_error(tav_cbor_value_int(value, &v), "read int");
            print_indent(indent);
            printf("int(%" PRId64 ")\n", v);
            break;
        }
        case TAV_CBOR_KIND_SIMPLE: {
            uint8_t v = 0;
            check_cose_error(tav_cbor_value_simple(value, &v), "read simple value");
            print_indent(indent);
            if (v == 20) {
                printf("false\n");
            } else if (v == 21) {
                printf("true\n");
            } else if (v == 22) {
                printf("null\n");
            } else if (v == 23) {
                printf("undefined\n");
            } else {
                printf("simple(%u)\n", v);
            }
            break;
        }
        case TAV_CBOR_KIND_BYTES: {
            const uint8_t *data = NULL;
            size_t len = 0;
            check_cose_error(tav_cbor_value_bytes(value, &data, &len), "read byte string");
            print_indent(indent);
            print_hex_bytes(data, len);
            printf("\n");
            break;
        }
        case TAV_CBOR_KIND_TEXT: {
            const char *text = NULL;
            size_t len = 0;
            check_cose_error(tav_cbor_value_text(value, &text, &len), "read text string");
            print_indent(indent);
            printf("text(");
            print_escaped_text(text, len);
            printf(")\n");
            break;
        }
        case TAV_CBOR_KIND_ARRAY:
            print_array(value, indent);
            break;
        case TAV_CBOR_KIND_MAP:
            print_map(value, indent);
            break;
        case TAV_CBOR_KIND_TAGGED: {
            uint64_t tag = 0;
            const TavCborValue *payload = NULL;
            check_cose_error(tav_cbor_value_tag(value, &tag), "read tag");
            check_cose_error(tav_cbor_value_tagged_payload(value, &payload), "read tag payload");
            print_indent(indent);
            printf("tag(%" PRIu64 ")\n", tag);
            if (tag == TAV_COSE_TAG_SIGN1) {
                print_cose_sign1(payload, indent + 1);
            } else {
                print_cbor_value(payload, indent + 1);
            }
            break;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <payload-hex>\n", argv[0]);
        return 1;
    }

    Buffer payload = decode_hex(argv[1]);

    TavCborValue *root = NULL;
    TavError *error = tav_cbor_value_from_bytes(payload.data, payload.len, &root);
    if (error != NULL) {
        TavErrorCode code = tav_error_code(error);
        fprintf(stderr, "parse CBOR payload: %s\n", tav_error_message(error));
        tav_error_free(error);
        free_buffer(&payload);
        return code == TAV_ERROR_OK ? 1 : (int)code;
    }

    printf("CBOR payload\n");
    print_cbor_value(root, 0);

    tav_cbor_value_free(root);
    free_buffer(&payload);
    return 0;
}
