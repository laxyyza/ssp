#include "ght.h"
#include <stdlib.h>
#include <string.h>

#define GHT_MAX_LOAD 0.7
#define GHT_MIN_LOAD 0.2
#define GHT_HASH_VAL 5381

#define GHT_BUCKET_INHEAP -1
#define GHT_BUDKET_INARRAY 0

static size_t 
ght_hash(const ght_t* ht, uint64_t key)
{
    return key % ht->size;
}

static void 
ght_calc_load(ght_t* ht)
{
    ht->load = (float)ht->count / ht->size;
}

static void 
ght_inc(ght_t* ht)
{
    ht->count++;
    ght_calc_load(ht);
}

static void 
ght_dec(ght_t* ht)
{
    ht->count--;
    ght_calc_load(ht);
}

static bool 
ght_do_insert(ght_t* ht, uint64_t key, void* data)
{
    size_t idx;
    ght_bucket_t* bucket;
    ght_bucket_t* parent;
    ght_bucket_t** next;

    idx = ght_hash(ht, key);
    bucket = ht->table + idx;

    if (bucket->key == key)
    {
        bucket->data = data;
        return true;
    }
    if (bucket->data)
    {
        parent = bucket;
        next = &parent->next;
        while (*next)
        {
            if (next[0]->key == key)
            {
                next[0]->data = data;
                return true;
            }
            next = &next[0]->next;
        }
        bucket = calloc(1, sizeof(ght_bucket_t));
        bucket->inheap = GHT_BUCKET_INHEAP;
        *next = bucket;
    }
    bucket->key = key;
    bucket->data = data;
    ght_inc(ht);
    return true;
}

static void 
ght_resize(ght_t* ht, size_t new_size)
{
    size_t old_size;
    ght_bucket_t* old_table;
    ght_bucket_t* old_bucket;
    ght_bucket_t* old_bucket_tmp;

    if (new_size < ht->min_size)
        new_size = ht->min_size;
    if (new_size == ht->size || ht->ignore_resize)
        return;

    old_size = ht->size;
    old_table = ht->table;

    ht->size = new_size;
    ht->table = calloc(new_size, sizeof(ght_bucket_t));
    ht->count = 0;

    for (size_t i = 0; i < old_size; i++)
    {
        old_bucket = old_table + i;
        do {
            if (old_bucket->data)
                ght_do_insert(ht, old_bucket->key, old_bucket->data);

            old_bucket_tmp = old_bucket->next;
            if (old_bucket->inheap)
                free(old_bucket);
            old_bucket = old_bucket_tmp;
        } while (old_bucket);
    }
    free(old_table);
}

static void 
ght_check_load(ght_t* ht)
{
    if (ht->load > ht->max_load)
        ght_resize(ht, ht->size * 2);
    else if (ht->load < ht->min_load)
        ght_resize(ht, ht->size / 2);
}

static void 
ght_del_bucket(ght_t* ht, ght_bucket_t* bucket)
{
    ght_bucket_t* next;

    if (ht->free)
        ht->free(bucket->data);
    if ((next = bucket->next))
    {
        if (bucket->inheap == GHT_BUDKET_INARRAY)
            next->inheap = GHT_BUDKET_INARRAY;
        memcpy(bucket, next, sizeof(ght_bucket_t));
        free(next);
    }
    else if (bucket->inheap == -1)
        free(bucket);
    else
        memset(bucket, 0, sizeof(ght_bucket_t));
    ght_dec(ht);
    ght_check_load(ht);
}

bool
ght_init(ght_t* ht, size_t initial_size, ght_free_t free_callback)
{
    if (initial_size == 0)
        return false;

    ht->table = calloc(initial_size, sizeof(ght_bucket_t));
    if (ht->table == NULL)
        return false;

    ht->size = initial_size;
    ht->min_size = initial_size;
    ht->count = 0;
    ht->free = free_callback;
    ht->load = 0.0;
    ht->max_load = GHT_MAX_LOAD;
    ht->min_load = GHT_MIN_LOAD;
    ht->ignore_resize = false;

    pthread_mutex_init(&ht->mutex, NULL);

    return true;
}

void 
ght_lock(ght_t* ht)
{
    pthread_mutex_lock(&ht->mutex);
}

void 
ght_unlock(ght_t* ht)
{
    pthread_mutex_unlock(&ht->mutex);
}

uint64_t     
ght_hashstr(const char* str)
{
    uint64_t hash = GHT_HASH_VAL;
    while (*str)
        hash = ((hash << 5) + hash) + (*str++);
    return hash;
}

bool    
ght_insert(ght_t* ht, uint64_t key, void* data)
{
    bool ret;

    if (!data)
        return false;

    ght_lock(ht);
    if ((ret = ght_do_insert(ht, key, data)))
        ght_check_load(ht);
    ght_unlock(ht);
    return ret;
}

void*   
ght_get(ght_t* ht, uint64_t key)
{
    void* ret = NULL;
    size_t idx;
    ght_bucket_t* bucket;

    ght_lock(ht);
    idx = ght_hash(ht, key);
    bucket = ht->table + idx;
    if (bucket->data == NULL)
        goto unlock;
    if (bucket->key == key)
    {
        ret = bucket->data;        
        goto unlock;
    }
    while (bucket && bucket->key != key)
        bucket = bucket->next;
    if (bucket)
        ret = bucket->data;
unlock:
    ght_unlock(ht);
    return ret;
}

bool    
ght_del(ght_t* ht, uint64_t key)
{
    ght_bucket_t* bucket;
    ght_bucket_t* prev;
    size_t idx;
    bool ret = true;

    ght_lock(ht);
    idx = ght_hash(ht, key);
    bucket = ht->table + idx;
    if (bucket->key == key)
    {
        ght_del_bucket(ht, bucket);
        goto unlock;
    }
    prev = bucket;
    while ((bucket = bucket->next))
    {
        if (bucket->key == key)
        {
            prev->next = NULL;
            ght_del_bucket(ht, bucket);
            goto unlock;
        }
        prev = bucket;
    }
    ret = false;
unlock:
    ght_unlock(ht);
    return ret;
}

void
ght_clear(ght_t* ht)
{
    ght_bucket_t* next;
    ght_bucket_t* bucket;

    ght_lock(ht);
    for (size_t i = 0; i < ht->size; i++)
    {
        bucket = ht->table + i;
        while (bucket && bucket->data)
        {
            if (ht->free)
                ht->free(bucket->data);

            next = bucket->next;
            if (bucket->inheap)
                free(bucket);
            bucket = next;
        }
    }
    ht->count = 0;
    ht->load = 0.0;
    ght_unlock(ht);
}

void
ght_destroy(ght_t* ht)
{
    if (ht->table == NULL)
        return;

    ght_clear(ht);
    pthread_mutex_destroy(&ht->mutex);
    free(ht->table);
}
