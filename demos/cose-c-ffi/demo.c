// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "tav/cose.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct Buffer {
    uint8_t *data;
    size_t len;
} Buffer;

static const uint8_t SAMPLE_CBOR[] = {
    0xa4,
    0x66, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72,
    0x67, 0x63, 0x6f, 0x6e, 0x74, 0x6f, 0x73, 0x6f,
    0x6b, 0x6d, 0x65, 0x61, 0x73, 0x75, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74,
    0x44, 0x01, 0x02, 0x03, 0x04,
    0x66, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x73,
    0x83, 0x01, 0xf5, 0xf6,
    0x66, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x72,
    0xa2, 0x01, 0x26, 0x63, 0x6b, 0x69, 0x64, 0x43, 0x0a, 0x0b, 0x0c,
};

static Buffer read_file(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        exit(1);
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek");
        exit(1);
    }

    long size = ftell(file);
    if (size < 0) {
        perror("ftell");
        exit(1);
    }
    rewind(file);

    Buffer buffer = {
        .data = malloc((size_t)size),
        .len = (size_t)size,
    };
    if (buffer.data == NULL && buffer.len != 0) {
        perror("malloc");
        exit(1);
    }

    if (buffer.len != 0 && fread(buffer.data, 1, buffer.len, file) != buffer.len) {
        perror("fread");
        exit(1);
    }

    fclose(file);
    return buffer;
}

static void free_buffer(Buffer *buffer) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->len = 0;
}

static void check_cose_error(TAVCoseError *error, const char *context) {
    if (error == NULL) {
        return;
    }

    TAVCoseErrorCode code = tav_cose_error_code(error);
    fprintf(stderr, "%s: %s\n", context, tav_cose_error_message(error));
    tav_cose_error_free(error);
    exit(code == TAV_COSE_ERROR_OK ? 1 : (int)code);
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

static void print_cbor_value(const TAVCborValue *value, size_t indent);

static void print_array(const TAVCborValue *value, size_t indent) {
    size_t len = 0;
    check_cose_error(tav_cbor_value_len(value, &len), "read array length");

    print_indent(indent);
    printf("array(len=%zu)\n", len);
    for (size_t i = 0; i < len; i++) {
        const TAVCborValue *child = NULL;
        check_cose_error(tav_cbor_value_array_at(value, i, &child), "read array child");
        print_indent(indent + 1);
        printf("[%zu]\n", i);
        print_cbor_value(child, indent + 2);
    }
}

static void print_map(const TAVCborValue *value, size_t indent) {
    size_t len = 0;
    check_cose_error(tav_cbor_value_len(value, &len), "read map length");

    print_indent(indent);
    printf("map(len=%zu)\n", len);
    for (size_t i = 0; i < len; i++) {
        const TAVCborValue *key = NULL;
        const TAVCborValue *child = NULL;
        check_cose_error(tav_cbor_value_map_key_at(value, i, &key), "read map key");
        check_cose_error(tav_cbor_value_map_value_at(value, i, &child), "read map value");

        print_indent(indent + 1);
        printf("entry[%zu].key\n", i);
        print_cbor_value(key, indent + 2);
        print_indent(indent + 1);
        printf("entry[%zu].value\n", i);
        print_cbor_value(child, indent + 2);
    }
}

static void print_cbor_value(const TAVCborValue *value, size_t indent) {
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
            const TAVCborValue *payload = NULL;
            check_cose_error(tav_cbor_value_tag(value, &tag), "read tag");
            check_cose_error(tav_cbor_value_tagged_payload(value, &payload), "read tag payload");
            print_indent(indent);
            printf("tag(%" PRIu64 ")\n", tag);
            print_cbor_value(payload, indent + 1);
            break;
        }
    }
}

int main(int argc, char **argv) {
    if (argc > 2) {
        fprintf(stderr, "usage: %s [payload.cbor]\n", argv[0]);
        return 1;
    }

    Buffer file = {0};
    const uint8_t *payload = SAMPLE_CBOR;
    size_t payload_len = sizeof(SAMPLE_CBOR);
    if (argc == 2) {
        file = read_file(argv[1]);
        payload = file.data;
        payload_len = file.len;
    }

    TAVCborValue *root = NULL;
    TAVCoseError *error = tav_cbor_value_from_bytes(payload, payload_len, &root);
    if (error != NULL) {
        TAVCoseErrorCode code = tav_cose_error_code(error);
        fprintf(stderr, "parse CBOR payload: %s\n", tav_cose_error_message(error));
        tav_cose_error_free(error);
        free_buffer(&file);
        return code == TAV_COSE_ERROR_OK ? 1 : (int)code;
    }

    printf("CBOR payload\n");
    print_cbor_value(root, 0);

    tav_cbor_value_free(root);
    free_buffer(&file);
    return 0;
}
