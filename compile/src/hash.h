#ifndef _HASH_H
#define _HASH_H

#define U_CHAR unsigned char

/* Option flags  */
#define HT_HISTORY 0x1

/*
------------------------------------------------------------------------
Type Definitions
------------------------------------------------------------------------
*/

/*  Individual element  */
typedef struct h_elem_s {
		/*  Key */
		U_CHAR  *key;
		int    nkey;
		/*  Data  */
		U_CHAR  *data;
		int    ndata;
		/*  Links to double linked list for each hash slot  */
		struct helem_s *next, *prev;
		/*  Links for global double linked list for element history  */
		/*  No space needed for these links if no history  */
		struct helem_s *newer, *older;
} helem_t;

/*  Hash  */
typedef struct {
		/*  Number of elements in all lists  */
		int     nelem;
		/*  Array of lists  */
		helem_t **array;
		/*  Size of array of lists  */
		int     narray;
		/*  Number of allocated lists:  nlist <= narray */
		int     nlist;
		/*  Current element,list  - used to find next  */
		helem_t *curelem;
		int      curlist;
		/*  This flag true/false to add new elements to list tail/head  */
		int     AddTail;
		/*  Use history list  */
		int     Options;
		/*  Size of element  */
		int     ElementSize;
		/*  Oldest, newest nodes  */
		helem_t *oldest, *newest;
} htable_t;


/*
------------------------------------------------------------------------
Function Prototypes
------------------------------------------------------------------------
*/

htable_t *ht_init      (int narray, int options);
int       ht_finddata  (htable_t *h, U_CHAR *k, int nk, U_CHAR **d, int *nd);
int       ht_storenode (htable_t *h, U_CHAR *k, int nk, U_CHAR  *d, int  nd);
void      ht_initwalk  (htable_t *h);
helem_t  *ht_getnext   (htable_t *h);
helem_t  *ht_getnewer  (htable_t *h, helem_t *e);
int       ht_getcount  (htable_t *h);
void      ht_free      (htable_t *h);
helem_t  *ht_findelem  (htable_t *h, U_CHAR *k, int nk);
int       ht_gethash   (htable_t *h, U_CHAR *k, int nk);
void      ht_freeelem  (htable_t *h, helem_t  *e);
void      ht_makenewest(htable_t *h, helem_t *);
helem_t  *ht_getoldest (htable_t *h);
void      ht_debuginfo (htable_t *h);

#endif
