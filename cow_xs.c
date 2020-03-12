#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>





typedef struct RefCounted {
    size_t refCount_;
    char data_[1];
} refcounted;

static size_t getDataOffset() {
      return offsetof(refcounted, data_);
}

static refcounted* fromData(char* p) {
    return (refcounted*)((void*)(size_t*)((void*) p - getDataOffset()));
}

static size_t refs(char* p) {
    return fromData(p)->refCount_;
}

static void incrementRefs(char* p) {
    fromData(p)->refCount_+=1;
}

static void decrementRefs(char* p) {
        refcounted *dis = fromData(p);
        size_t oldcnt = (dis->refCount_--);
        if (oldcnt == 1) {
            free(dis);
      }
}


static char *create(const char* data, size_t size) {
    refcounted *result =malloc(getDataOffset() + (size + 1) * sizeof(char));
    result->refCount_ = 0;
    memcpy(result->data_, data, strlen(data)+1);
    return result->data_;
}


typedef union {
    /* allow strings up to 15 bytes to stay on the stack
     * use the last byte as a null terminator and to store flags
     * much like fbstring:
     * https://github.com/facebook/folly/blob/master/folly/docs/FBString.md
     */
    char data[16];

    struct {
        uint8_t filler[15],
            /* how many free bytes in this stack allocated string
             * same idea as fbstring
             */
            space_left : 4,
            /* if it is on heap, set to 1 */
            is_ptr : 1, flag1 : 1, flag2 : 1, flag3 : 1;
    };

    /* heap allocated */
    struct {
        char *ptr;
        /* supports strings up to 2^54 - 1 bytes */
        size_t size : 54,
            /* capacity is always a power of 2 (unsigned)-1 */
            capacity : 6;
        /* the last 4 bits are important flags */
    };
} xs;

static inline bool xs_is_ptr(const xs *x) { return x->is_ptr; }
static inline size_t xs_size(const xs *x)
{
    return xs_is_ptr(x) ? x->size : 15 - x->space_left;
}
static inline char *xs_data(const xs *x)
{
    return xs_is_ptr(x) ? (char *) x->ptr : (char *) x->data;
}
static inline size_t xs_capacity(const xs *x)
{
    return xs_is_ptr(x) ? ((size_t) 1 << x->capacity) - 1 : 15;
}

#define xs_literal_empty() \
    (xs) { .space_left = 15 }

static inline int ilog2(uint32_t n) { return 32 - __builtin_clz(n) - 1; }



xs *cow_cpy(xs *dst, xs *src){
    if (xs_is_ptr(src)){
        dst->is_ptr = true;
        dst->ptr = src->ptr;
        dst->size = src->size;
        dst->capacity = src->capacity;;
        incrementRefs(xs_data(src));
    }
    else{
        dst->is_ptr = false;
        dst->space_left = src->space_left;
        memcpy(dst->data , src->data, xs_size(src));
    }
    return dst;
}



xs *xs_new(xs *x, const void *p)
{
    *x = xs_literal_empty();
    size_t len = strlen(p) + 1;
    if (len > 16) {
        x->capacity = ilog2(len) + 1;
        x->size = len - 1;
        x->is_ptr = true;
        x->ptr = create(p, len);
        memcpy(x->ptr, p, len);
    } else {
        memcpy(x->data, p, len);
        x->space_left = 15 - (len - 1);
    }
    return x;
}

/* Memory leaks happen if the string is too long but it is still useful for
 * short strings.
 * "" causes a compile-time error if x is not a string literal or too long.
 */
/*
#define xs_tmp(x)                                          \
    ((void) ((struct {                                     \
         _Static_assert(sizeof(x) <= 16, "it is too big"); \
         int dummy;                                        \
    }){1}),                                               \
    xs_new(&xs_literal_empty(), "" x))

*/
#define xs_tmp(x) xs_new(&xs_literal_empty(), x)




/* grow up to specified size */
xs *xs_grow(xs *x, size_t len)
{
    if (len <= xs_capacity(x))
        return x;
    size_t cap = ilog2(len) + 1;
    if (xs_is_ptr(x))
        x->ptr = realloc(x->ptr, (size_t) 1 << cap);
    else {
        char buf[16];
        memcpy(buf, x->data, 16);
        x->ptr = create(xs_data(x), len);
    }
    x->is_ptr = true;
    x->capacity = cap;
    return x;
}

static inline xs *xs_newempty(xs *x)
{
    *x = xs_literal_empty();
    return x;
}

static inline xs *xs_free(xs *x)
{
    if (xs_is_ptr(x))
        decrementRefs(xs_data(x));
    return xs_newempty(x);
}

xs *xs_concat(xs *string, const xs *prefix, const xs *suffix)
{
    if (xs_is_ptr(string)) {
        if (refs(string->data) > 0) {
            decrementRefs(xs_data(string));
            string->ptr = create(xs_data(string), xs_size(string));
        }
    }
    size_t pres = xs_size(prefix), sufs = xs_size(suffix),
           size = xs_size(string), capacity = xs_capacity(string);

    char *pre = xs_data(prefix), *suf = xs_data(suffix),
         *data = xs_data(string);
    printf("concat len:%zu\n",size + pres + sufs);
    printf("capacity:%ld\n",capacity);
    if (size + pres + sufs <= capacity) {
        memmove(data + pres, data, size);
        memcpy(data, pre, pres);
        memcpy(data + pres + size, suf, sufs + 1);
        string->space_left = 15 - (size + pres + sufs);
    } else {
        xs tmps = xs_literal_empty();
        xs_grow(&tmps, size + pres + sufs);
        char *tmpdata = xs_data(&tmps);
        memcpy(tmpdata + pres, data, size);
        memcpy(tmpdata, pre, pres);
        memcpy(tmpdata + pres + size, suf, sufs + 1);
        xs_free(string);
        *string = tmps;
        printf("concat string len:%zu\n",string->size );
        string->size = size + pres + sufs;
    }
    return string;
}

xs *xs_trim(xs *x, const char *trimset)
{
    if (!trimset[0])
        return x;

    char *dataptr = xs_data(x), *orig = dataptr;

    /* similar to strspn/strpbrk but it operates on binary data */
    //BBB
    uint8_t mask[32] = {0};
//CCC 
#define check_bit(byte) (mask[(uint8_t) byte / 8] & (1 << (uint8_t) byte % 8))
#define set_bit(byte) (mask[(uint8_t) byte / 8] |= (1 << (uint8_t) byte % 8))

    size_t i, slen = xs_size(x), trimlen = strlen(trimset);

    for (i = 0; i < trimlen; i++)
        set_bit(trimset[i]);
    for (i = 0; i < slen; i++)
        if (!check_bit(dataptr[i]))
            break;
    for (; slen > 0; slen--)
        if (!check_bit(dataptr[slen - 1]))
            break;
    dataptr += i;
    slen -= i;

    /* reserved space as a buffer on the heap.
     * Do not reallocate immediately. Instead, reuse it as possible.
     * Do not shrink to in place if < 16 bytes.
     */
    if (xs_is_ptr(x) & (slen != xs_size(x))) {
        if (refs(x->data) > 0) {
            decrementRefs(xs_data(x));
            x->ptr = create(xs_data(x), xs_size(x));
            orig = xs_data(x);
        }
    }
    memmove(orig, dataptr, slen);
    /* do not dirty memory unless it is needed */
    if (orig[slen])
        orig[slen] = 0;

    if (xs_is_ptr(x))
        x->size = slen;
    else
        x->space_left = 15 - slen;
    return x;
#undef check_bit
#undef set_bit
}




int main()
{
    xs string = *xs_tmp("()string()");
    xs_trim(&string, ")(");
    printf("[%s] : %2zu\n", xs_data(&string), xs_size(&string));
    xs prefix = *xs_tmp("^^^^^^^^"), suffix = *xs_tmp("^^^^^^^^");
    xs_concat(&string, &prefix, &suffix);
    printf("[%s] : %2zu\n", xs_data(&string), xs_size(&string));
    printf("before copy string refcount: %ld\n", refs(string.ptr));
    xs copystring = *cow_cpy(&xs_literal_empty(), &string);
    printf("after copy string refcount : %ld\n", refs(string.ptr));
    printf("copystring refcount : %ld\n", refs(copystring.ptr));
    return 0;
}