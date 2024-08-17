#include "ght.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PNAME_MAX 32

typedef struct 
{
    char    name[PNAME_MAX];
    char    lastname[PNAME_MAX];
    int     age;
} person_t;

static void
print_ght(const ght_t* ht)
{
    printf("GHT: { count: %lu, array_size: %lu, load: %.1f, min/max_load: %.1f/%.1f }\n", 
           ht->count, ht->size, ht->load, ht->min_load, ht->max_load);
    printf("[\n");
    if (ht->count == 0)
        printf("\t[EMPTY]\n");
    else
    {
        GHT_FOREACH(person_t* p, ht,
        {
            printf("\t{ '%s' '%s' %d years old. },\n", 
                   p->name, p->lastname, p->age);
        });
    }
    printf("]\n");
}

static void 
add_person(ght_t* ht, const char* name, const char* last, int age)
{
    uint64_t name_hash;
    person_t* p = calloc(1, sizeof(person_t));

    strncpy(p->name, name, PNAME_MAX);
    strncpy(p->lastname, last, PNAME_MAX);
    p->age = age;

    name_hash = ght_hashstr(name);

    ght_insert(ht, name_hash, p);
}

static void
del_person(ght_t* ht, const char* name)
{
    uint64_t name_hash = ght_hashstr(name);

    printf("Removing '%s'... ", name);
    if (ght_del(ht, name_hash))
        printf("OK.\n");
    else
        printf("Not found.\n");
}

static void
find_person(ght_t* ht, const char* name)
{
    person_t* p;
    uint64_t name_hash = ght_hashstr(name);

    printf("Searching for '%s'... ", name);
    if ((p = ght_get(ht, name_hash)))
        printf("Found!\n\t{ '%s' '%s' %d years old }\n",
               p->name, p->lastname, p->age);
    else
        printf("Not found.\n");
}

static void
do_example(ght_t* ht)
{
    printf(" ----- Initial ADDs -----\n");
    print_ght(ht);
    add_person(ht, "Bubba", "McFiddlesticks", 69);
    add_person(ht, "Dorkus", "Bumblebottom", 420);
    add_person(ht, "Booger", "Snodgrass", 12);
    add_person(ht, "Wanda-May", "Waddlebottom", 31);
    print_ght(ht);

    printf("\n");
    printf(" ----- Now searches -----\n");
    find_person(ht, "Booger");
    find_person(ht, "Bubba");
    find_person(ht, "Jeff");
    printf("\n");

    printf(" ----- Now removes -----\n");
    del_person(ht, "Dorkus");
    del_person(ht, "Booger");
    del_person(ht, "Jeff");
    print_ght(ht);

    printf("\n");
    printf(" ----- Now searches removed -----\n");
    find_person(ht, "Booger");
    find_person(ht, "Dorkus");
    find_person(ht, "Bubba");
    printf("\n");

    del_person(ht, "Wanda-May");
    print_ght(ht);

    printf("\n");

    del_person(ht, "Bubba");
    print_ght(ht);
}

int 
main(void)
{
    ght_t ht;
    // Initialize with size of 1, utilize the dynamic-sizing.
    if (ght_init(&ht, 1, free /* libc free() */) == false)
    {
        fprintf(stderr, "ght_init() failed.\n");
        return -1;
    }
    do_example(&ht);

    // clear table, free array, destory mutex.
    ght_destroy(&ht);

    return 0;
}
