/*
  From ccan https://ccodearchive.net/list.html

  Copyright (C) 2011 Joseph A. Adams (joeyadams3.14159@gmail.com)
  All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

/**
 * json - Parse and generate JSON (JavaScript Object Notation)
 *
 * This is a library for encoding and decoding JSON that strives to be
 * easy to learn, use, and incorporate into an application.
 *
 * JSON (JavaScript Object Notation) facilitates passing data among different
 * programming languages, particularly JavaScript.  It looks like this:
 *
 *     [
 *         {
 *             "id":           1,
 *             "firstname":    "John",
 *             "lastname":     "Smith",
 *             "email":        "john@example.com",
 *             "likes_pizza":  false
 *         },
 *         {
 *             "id":           2,
 *             "firstname":    "Linda",
 *             "lastname":     "Jones",
 *             "email":        null,
 *             "likes_pizza":  true
 *         }
 *     ]
 *
 * Example:
 *    #include <ccan/json/json.h>
 *    #include <math.h>
 *    #include <stdio.h>
 *    #include <stdlib.h>
 *
 *    static int find_number(JsonNode *object, const char *name, double *out)
 *    {
 *        JsonNode *node = json_find_member(object, name);
 *        if (node && node->tag == JSON_NUMBER) {
 *            *out = node->number_;
 *            return 1;
 *        }
 *        return 0;
 *    }
 *
 *    static void solve_pythagorean(JsonNode *triple)
 *    {
 *        double a = 0, b = 0, c = 0;
 *        int a_given, b_given, c_given;
 *
 *        if (triple->tag != JSON_OBJECT) {
 *            LOG(LEVEL_ERROR, "Expected a JSON object.\n");
 *            exit(EXIT_FAILURE);
 *        }
 *
 *        a_given = find_number(triple, "a", &a);
 *        b_given = find_number(triple, "b", &b);
 *        c_given = find_number(triple, "c", &c);
 *
 *        if (a_given + b_given + c_given != 2) {
 *            LOG(LEVEL_ERROR, " need two sides to compute the length of the
 * third.\n"); exit(EXIT_FAILURE);
 *        }
 *
 *        if (a_given && b_given) {
 *            c = sqrt(a*a + b*b);
 *            json_append_member(triple, "c", json_mknumber(c));
 *        } else if (a_given && c_given) {
 *            b = sqrt(c*c - a*a);
 *            json_append_member(triple, "b", json_mknumber(b));
 *        } else if (b_given && c_given) {
 *            a = sqrt(c*c - b*b);
 *            json_append_member(triple, "a", json_mknumber(a));
 *        }
 *    }
 *
 *    int main(void)
 *    {
 *        JsonNode *triples = json_mkarray();
 *
 *        json_append_element(triples, json_decode("{\"a\": 3, \"b\": 4}"));
 *        json_append_element(triples, json_decode("{\"a\": 5, \"c\": 13}"));
 *        json_append_element(triples, json_decode("{\"b\": 24, \"c\": 25}"));
 *
 *        JsonNode *triple;
 *        json_foreach(triple, triples)
 *            solve_pythagorean(triple);
 *
 *        char *tmp = json_stringify(triples, "\t");
 *        puts(tmp);
 *        free(tmp);
 *
 *        json_delete(triples);
 *        return 0;
 *    }
 *
 * Author: Joey Adams
 * Version: 0.1
 * License: MIT
 */

#ifndef CRYPTO_JSON_H
#define CRYPTO_JSON_H

#include <stddef.h>
#include <stdbool.h>

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_STRING,
    JSON_NUMBER,
    JSON_ARRAY,
    JSON_OBJECT,
} JsonTag;

typedef struct JsonNode JsonNode;

struct JsonNode {
    /* only if parent is an object or array (NULL otherwise) */
    JsonNode *parent;
    JsonNode *prev, *next;

    /* only if parent is an object (NULL otherwise) */
    char *key; /* Must be valid UTF-8. */

    JsonTag tag;
    union {
        /* JSON_BOOL */
        bool bool_;

        /* JSON_STRING */
        char *string_; /* Must be valid UTF-8. */

        /* JSON_NUMBER */
        double number_;

        /* JSON_ARRAY */
        /* JSON_OBJECT */
        struct {
            JsonNode *head, *tail;
        } children;
    };
};

/*** Encoding, decoding, and validation ***/

JsonNode *json_decode(const char *json);
char     *json_encode(const JsonNode *node);
char     *json_encode_string(const char *str);
char     *json_stringify(const JsonNode *node, const char *space);
void      json_delete(JsonNode *node);

bool json_validate(const char *json);

/*** Lookup and traversal ***/

JsonNode *json_find_element(JsonNode *array, int index);
JsonNode *json_find_member(JsonNode *object, const char *key);

JsonNode *json_first_child(const JsonNode *node);

#define json_foreach(i, object_or_array)                                       \
    for ((i) = json_first_child(object_or_array); (i) != NULL; (i) = (i)->next)

/*** Construction and manipulation ***/

JsonNode *json_mknull(void);
JsonNode *json_mkbool(bool b);
JsonNode *json_mkstring(const char *s);
JsonNode *json_mknumber(double n);
JsonNode *json_mkarray(void);
JsonNode *json_mkobject(void);

void json_append_element(JsonNode *array, JsonNode *element);
void json_prepend_element(JsonNode *array, JsonNode *element);
void json_append_member(JsonNode *object, const char *key, JsonNode *value);
void json_prepend_member(JsonNode *object, const char *key, JsonNode *value);

void json_remove_from_parent(JsonNode *node);

/*** Debugging ***/

/*
 * Look for structure and encoding problems in a JsonNode or its descendents.
 *
 * If a problem is detected, return false, writing a description of the problem
 * to errmsg (unless errmsg is NULL).
 */
bool json_check(const JsonNode *node, char errmsg[256]);

#endif
