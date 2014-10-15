#ifndef _IPDBASE_H
#define _IPDBASE_H

/*
------------------------------------------------------------------------
Inlucde files
------------------------------------------------------------------------
*/
#include "hash.h"

/*
------------------------------------------------------------------------
Exported Functions
------------------------------------------------------------------------
*/

/*
Retrieve and print packets from hash table in bin format
*/
void bin_writepkt (htable_t *ht, char *outname);
void txt_writepkt (htable_t *ht, char *outname);
void sql_writepkt (htable_t *ht, char *outname);

#endif
