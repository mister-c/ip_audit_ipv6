/* hash.c
 *
 * hash.c - basic hash table functions
 * By Jon Rifkin <j.rifkin@uconn.edu>
 * Copyright 1999,2001 Jonathan Rifkin
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


/*
------------------------------------------------------------------------
Compile Switches
------------------------------------------------------------------------
*/

/*
 * Add  #define TEST_DRIVER
 * to compile test driver routine
 */



/*
------------------------------------------------------------------------
Include files
------------------------------------------------------------------------
*/
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include "hash.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/


/*
------------------------------------------------------------------------
Macros
------------------------------------------------------------------------
*/
#define WRITEMSG \
   printf ("File %s line %d\n", __FILE__, __LINE__); fflush(stdout);
#define WRITETXT(TXT) \
   printf ("File %s line %d: %s\n", __FILE__, __LINE__, TXT); fflush(stdout);
#define WRITEVAR(VAR,FMT) \
   printf ("File %s line %d: ", __FILE__, __LINE__); \
	printf ("%s <", #VAR); \
	printf (#FMT, VAR); \
	printf (">\n"); fflush(stdout);

#define UINT4  unsigned int

#define NRSEQ  256


/*
------------------------------------------------------------------------
Typedefs
------------------------------------------------------------------------
*/



/*
------------------------------------------------------------------------
Module variables
------------------------------------------------------------------------
*/

/*
Random sequence table - source of random numbers.  The
hash routine 'amplifies' this 2**8 long sequence into
a 2**32 long sequence.
*/
static U_CHAR rseq_m[NRSEQ+3] =
{
 79,181, 35,147, 68,177, 63,134,103,  0, 34, 88, 69,221,231, 13,
 91, 49,220, 90, 58,112, 72,145,  7,  4, 93,176,129,192,  5,132,
 86,142, 21,148, 37,139, 39,169,143,224,251, 64,223,  1,  9,152,
 51, 66, 98,155,180,109,149,135,229,137,215, 42, 62,115,246,242,
118,160, 94,249,123,144,122,213,252,171, 60,167,253,198, 77,  2,
154,174,168, 52, 27, 92,226,233,205, 10,208,247,209,113,211,106,
163,116, 65,196, 73,201, 23, 15, 31,140,189, 53,207, 83, 87,202,
101,173, 28, 46,  6,255,237, 47,227, 36,218, 70,114, 22,100, 96,
182,117, 43,228,210, 19,191,108,128, 89, 97,153,212,203, 99,236,
238,141,  3, 95, 29,232,  8, 75, 57, 25,159, 24,131,162, 67,119,
 74, 30,138,214,240, 12,187,127,133, 18, 81,222,188,239, 82,199,
186,166,197,230,126,161,200, 40, 59,165,136,234,250, 44,170,157,
190,150,105, 84, 55,204, 56,244,219,151,178,195,194,110,184, 14,
 48,146,235,216,120,175,254, 50,102,107, 41,130, 54, 26,248,225,
111,124, 33,193, 76,121,125,158,185,245, 16,206, 71, 45, 20,179,
 32, 38,241, 80, 85,243, 11,217, 61, 17, 78,172,156,183,104,164,
 79,181, 35
};     

int   is_rseq_init_m = 0;
UINT4 r0_m[256], r1_m[256], r2_m[256], r3_m[256]; 


/*
------------------------------------------------------------------------
Local Function Prototypes
------------------------------------------------------------------------
*/
UINT4 foldkey (U_CHAR *key, int keylength);
UINT4 makehash( UINT4 );
double mrand ( UINT4 );
void init_rand_sequence(void);


/*
------------------------------------------------------------------------
Exported Functions
------------------------------------------------------------------------
*/


htable_t *ht_init (int narray, int options) {
	htable_t *ht = NULL;


	ht = (htable_t *) calloc(1, sizeof(htable_t));
	if (NULL==ht) return NULL;

	ht->narray  = narray;
	ht->array   = (helem_t **) calloc(ht->narray,sizeof(helem_t *));
	ht->nelem   = 0;
	ht->curelem = NULL;
	ht->curlist = 0;
	ht->AddTail = 0;
	ht->newest  = NULL;
	ht->oldest  = NULL;
	ht->Options = options;
	ht->ElementSize = sizeof(helem_t);

	/*  Could not allocate array, return NULL for hash table  */
	if (NULL==ht->array) {
		free(ht);
		ht = NULL;
	}

	/*  Reduce element size if no history  */
	if (! (ht->Options & HT_HISTORY) ) 
		ht->ElementSize = sizeof (helem_t) - 2 * sizeof(helem_t *);

	/*  Make sure random sequence tables are initiated  */
	if (!is_rseq_init_m) {
		init_rand_sequence();
		is_rseq_init_m = 1;
	}
	return ht;
}



/*  Returns hash value  */
int ht_gethash  (htable_t *ht, U_CHAR *key, int nkey) {
	static double f = 1.0/4294967296.0;
	return (int) ( ht->narray * f *foldkey(key, nkey) );
}



/*  Returns pointer to element (or null if not found) */
helem_t *ht_findelem (htable_t *ht, U_CHAR *key, int nkey) {
	int hash;
	helem_t *e;

	hash = ht_gethash (ht, key, nkey);

	/*  No list for this hash slot -> not found  */
	if (NULL==ht->array[hash]) {
		return NULL;
	}

	/*  Search list  */
	e = ht->array[hash];
	while (NULL!=e) {
      /*  Found key  */
		if (e->nkey==nkey && ! memcmp(e->key, key, nkey))  {
			return e;
		}
		e = (helem_t *) e->next;
	}

	/*  Key not found on list  */
	return NULL;
}



/*  Remove element from table and free its storage  */
void ht_freeelem (htable_t *ht, helem_t *e) {
	helem_t *prev, *next;
	int hash;

	
	/*  Return if null pointer  */
	if (!e) return;

	/*  Find and fix hash table entry if it points to deleted element  */
	hash = ht_gethash(ht, e->key, e->nkey);
	if (ht->array[hash]==e) ht->array[hash] = (helem_t *)e->next;

	/*  Adjust hash table list pointers for neighbors  */
	prev = (helem_t *) e->prev;
	next = (helem_t *) e->next;
	if (next) next->prev = (struct helem_s *) prev;
	if (prev) prev->next = (struct helem_s *) next;

	/*  Adjust history table list pointers for neighbors  */
	if (ht->Options & HT_HISTORY) {
		if (ht->oldest==e) ht->oldest = (helem_t *) e->newer;
		if (ht->newest==e) ht->newest = (helem_t *) e->older;
		prev = (helem_t *) e->older;
		next = (helem_t *) e->newer;
		if (next) next->older = (struct helem_s *) prev;
		if (prev) prev->newer = (struct helem_s *) next;
	}

	/*  Free storage  */
	if (e->data) free(e->data);
	if (e->key ) free(e->key );
	free(e);

	/*  Reduce count  */
	ht->nelem--;
}



/*  Returns 0/1 for not/is found  */
int ht_findkey 
(htable_t *ht, U_CHAR *key, int nkey, U_CHAR **data, int *ndata) {
	helem_t *e;

	e = ht_findelem (ht, key, nkey);

	/*  No list for this hash slot -> not found  */
	if (NULL==e) {
		*data  = NULL;
		*ndata = 0;
		return 0;
	}

	/*  Search list  */
	*data  = e->data;
	*ndata = e->ndata;
	return 1;
}


/*  Free key storage  */
void ht_freekey(htable_t *ht, U_CHAR *key, int nkey) {
	helem_t *e;

	e = ht_findelem (ht, key, nkey);

	/*   No element, return  */
	if (!e) return;

	/*  Free space  */
	ht_freeelem(ht,e);
}

/*  Add node to list  */
int ht_storekey (htable_t *ht, U_CHAR *key, int nkey, U_CHAR *data, int ndata) {
	int hash;
	helem_t *prev;
	helem_t *curr;
	helem_t *next;
	helem_t *temp;

	/*  Find hash  */
	hash = ht_gethash (ht, key, nkey);
	
	/*  Search table for existing node  */
	if (ht->array[hash]) {
		prev = NULL;
		curr = ht->array[hash];
		while (curr) {

			/*  Existing node with same key, replace the data  */
			if ( curr->nkey==nkey &&  ! memcmp(curr->key,key,nkey) ) {
				/*  Reallocate data storage if necessary  */
				if (curr->ndata!=ndata) {
					if (curr->ndata) free(curr->data);
					if (ndata      ) calloc(1, ndata);
				}
				/*  No data, just key  */
				if (NULL==data || 0==ndata) {
					curr->data  = NULL;
					curr->ndata = 0;
				} else {
					curr->ndata = ndata;
					memcpy(curr->data, data, ndata);	
				}
				/*  Make this the newest element  */
				ht_makenewest(ht, curr);
				return 0;
			}
			prev = curr;
			curr = (helem_t *) curr->next;
		}
	}

	/*  If reached here then key not found  */
	ht->nelem++;

	/*  Make a new node (unattached to list)  */
	/*    Don't allocate history pointers if no history  */
	temp        = (helem_t  *) calloc(1, ht->ElementSize);
	temp->key   = (U_CHAR   *) calloc(1, nkey);
	temp->data  = (U_CHAR   *) calloc(1, ndata);
	temp->nkey  = nkey;
	temp->ndata = ndata;
	temp->next  = NULL;
	temp->prev  = NULL;
	memcpy(temp->key,  key,  nkey);
	memcpy(temp->data, data, ndata);

	/*  First node in list */
	if (NULL==ht->array[hash])  {
		ht->array[hash] = temp;
	/*  Add node to list tail  */
	} else if (ht->AddTail) {
		prev->next = (struct helem_s *) temp;
		temp->prev = (struct helem_s *) prev;
	/*  Add node to list head  */
	} else {
		next = ht->array[hash];
		ht->array[hash] = temp;
		temp->next = (struct helem_s *) next;
		next->prev = (struct helem_s *) temp;
	}

	/*  Add node to start of history list  */
	if (ht->Options & HT_HISTORY) {
			  prev = ht->newest;
			  if (prev) prev->newer = (struct helem_s *) temp;
			  temp->older = (struct helem_s *) prev;
			  temp->newer = (struct helem_s *) NULL;
			  ht->newest  = temp;

			  if (!ht->oldest) ht->oldest = temp;
	}

	return 0;
}


/*  Get oldest element from histor list  */
helem_t *ht_getoldest (htable_t *ht) {
	return ht->oldest;
}

/*  Return element newer than element passed a argument */
helem_t *ht_getnewer (htable_t *ht, helem_t *helem) {
	/*   Return newer element  */
	if (ht->Options & HT_HISTORY) 
		/*  Need to convert helem_s* to helem_t*  */
		return (helem_t *) helem->newer;
	/*  No history kept, just return null  */
	else
		return NULL;
}


/*  Make element the newest in the history list  */
void ht_makenewest (htable_t *ht, helem_t *e) {
	/*  No history  */
	if (! (ht->Options & HT_HISTORY) ) return;
	/*  Null element  */
	if (!e) return;
	/*  Element already first  */
	if (e==ht->newest) return;
	/*  Unlink element as oldest element in list  */
	if (e==ht->oldest) {
		ht->oldest = (helem_t *) e->newer;
		ht->oldest->older = NULL;
	/*  Unlink element from current position in list  */
	} else {
		((helem_t *) e->newer)->older = e->older;
		((helem_t *) e->older)->newer = e->newer;
	}
	/*  Link element to start of list  */
	ht->newest->newer = (struct helem_s *) e;
	e->older          = (struct helem_s *) ht->newest;
	e->newer          = NULL;
	ht->newest        = e;
}


/*  Find first existing node  */
void ht_initwalk (htable_t *ht) {
	ht->curlist = 0;
	while (ht->curlist<ht->narray && NULL==ht->array[ht->curlist]) {
		ht->curlist++;
	}
	ht->curelem = (ht->curlist<ht->narray) ? ht->array[ht->curlist] : NULL;
}


/*   
 *   Return elements one at a time - returns 1/0 if data found/not-found
 *   (so can do handy code:   while (getnext(..)) { do stuff }
 */
helem_t *ht_getnext (htable_t *ht) {

	/*  Store current node for later return  */
	helem_t *current = ht->curelem;

	/*  End of table - return NULL  */
	if (current==NULL)  return NULL;
			
	/*  Set next element to next in list  */
	if (NULL!=ht->curelem->next) {
		ht->curelem = (helem_t *) ht->curelem->next;

	/*  check remaining lists in array */
	} else {
		ht->curlist++;
		while (ht->curlist<ht->narray && NULL==ht->array[ht->curlist]) 
			ht->curlist++;
		/*  No more lists with elements in them  */
		if (ht->curlist==ht->narray) {
			ht->curelem=NULL;
		} else {
			ht->curelem = ht->array[ht->curlist];
		}
	}

	/*  return data found  */
	return current;

}

int ht_getcount (htable_t *ht) {
	return ht->nelem;
}


void ht_free (htable_t *ht) {
	helem_t *current, *next;
	int i;

	if (NULL==ht) return;

	/*  No array (?) - just free structure and return  */
	if (NULL==ht->array) {
		free(ht);
		return;
	}

	/*  Scan array for linked lists  */
	for (i=0;i<ht->narray;i++) {
		current = ht->array[i];
		/*  Traverse linked list  */
		while (current) {
			next = (helem_t *) current->next;
			if (current->data) free(current->data);
			if (current->key ) free(current->key);
			free (current);
			current = next;
		}
	}

	/*  Free array  */
	free(ht->array);

	/*  Free structure  */
	free (ht);
}

void ht_debuginfo(htable_t *ht) {
	helem_t *current;
	int i;
	int nelem=0, nlist=0, maxlist=0, curlist=0;

	/*  Scan array for linked lists  */
	if (ht)
	for (i=0;i<ht->narray;i++) {
		current = ht->array[i];
		/*  Traverse linked list  */
		if (current) nlist++;
		curlist=0;
		while (current)  {
			curlist++;
			current = (helem_t *) current->next;
		}
		nelem+=curlist;
		if (curlist>>maxlist) maxlist = curlist;
	}

	printf ("Number of hash table slots         %d\n", ht->narray);
	printf ("Number of hash table slots used    %d\n", nlist);
	printf ("Number of elements stored in table %d\n", nelem);
	printf ("Longest linked list                %d\n", maxlist);
}




/*
------------------------------------------------------------------------
Local Functions
------------------------------------------------------------------------
*/


/*
 *'Folds' n-byte key into 4 byte key
 */
UINT4 foldkey  (U_CHAR *key, int keylength) {
	UINT4 fkey = 0;
	int i;

	for (i=0;i<keylength-4;i+=4) {
		fkey ^= makehash(* (UINT4 *) (key+i));
	}

	if (i==keylength) return fkey;

	for (;i<keylength;i++) 
		((U_CHAR *) &fkey)[i & 0x3] ^= key[i];

	return makehash(fkey);
}



/*
Hash function - performs a one to one mapping between
input integer and output integers, in other words, two different
input integers a_i, a_j will ALWAYS result in two different output
makehash(a_i) and makehash(a_j).

This hash function is designed so that a changing just one
bit in input 'a' will potentially affect the every bit in makehash(a),
and the correlation between succesive hashes is (hopefully) extremely
small (if not zero).

It can be used as a quick, dirty, portable and open source random
number generator that generates randomness on all 32 bits.
Use wrapper function mrand(n) to obtain floating point random
number r  0.0 <= r < 1.0

*/

void init_rand_sequence(void) {
	int i,j,mask1,mask2,mask3;
	char *r;

	/*  Test for little-end, big-endian  */
	i=1;
	if ((* (char *) &i)==1) {
		mask1 = 0x00ffffff;
		mask2 = 0x0000ffff;
		mask3 = 0x000000ff;
	} else {
		mask1 = 0xffffff00;
		mask2 = 0xffff0000;
		mask3 = 0xff000000;
	}

	/*  Make arrays  */
	r = (char *) r0_m;
	for (i=0;i<256;i++) 
	for (j=0;j<4;j++) 
		*(r++)  = rseq_m[(i+j)%256];

	for (i=0;i<256;i++) {
		r1_m[i] = r0_m[i] & mask1;
		r2_m[i] = r0_m[i] & mask2;
		r3_m[i] = r0_m[i] & mask3;
	}

}

UINT4 makehash(UINT4 a) {
   UINT4 b;
   U_CHAR *ap = (U_CHAR *) &a;
   U_CHAR *bp = (U_CHAR *) &b;
   int i;

	b =    r0_m[ap[0]] + r1_m[ap[1]] + r2_m[ap[2]] + r3_m[ap[3]];
	return r0_m[bp[0]] + r1_m[bp[1]] + r2_m[bp[2]] + r3_m[bp[3]];
}


/*  Map hash value into number  0.0<= n < 1.0  */
double mrand (UINT4 a) {
	static double f = 1.0/4294967296.0;
   return f*makehash(a);
}   
 


/*
------------------------------------------------------------------------
Test driver
------------------------------------------------------------------------
*/
/*  
 *  Driver needs to be re-written to account for changes made above 
 *  (JR 2001-10-30) 
 */
#ifdef TEST_DRIVER
int main () {
	htable_t *ht1, *ht2;
	U_CHAR *k1 = "Jeff"; 
	U_CHAR *d1 = "Ford";
	U_CHAR *k2 = "Bob Wigglesworth";
	U_CHAR *d2 = "Mercedes";
	U_CHAR *res = NULL;
	U_CHAR *rkey, *rdata;
	U_CHAR  bkey[256];
	U_CHAR  bdata[256];
	U_CHAR  buffer[256];
	int   klen, dlen;
	int   lres = 0;
	FILE  *infile = NULL;
	helem_t *e = NULL;


	ht1 = ht_init(1000,0);
	printf ("ht1 <%p>\n", ht1);
	printf ("ht1->array <%p>\n", ht1->array);

	ht_storekey (ht1, k1, strlen(k1)+1, d1, strlen(d1)+1);
	ht_storekey (ht1, k2, strlen(k2)+1, d2, strlen(d2)+1);

	ht_findkey (ht1, k1, strlen(k1)+1, &res, &lres);
	printf ("k1 res <%s> <%s>\n", k1, res);



	ht2 = ht_init(50,0);
	printf ("ht2 <%p>\n", ht2);
	printf ("ht2->array <%p>\n", ht2->array);

	ht_storekey (ht2, k1, strlen(k1)+1, d1, strlen(d1)+1);
	ht_storekey (ht2, k2, strlen(k2)+1, d2, strlen(d2)+1);

	ht_findkey (ht2, k1, strlen(k1)+1, &res, &lres);
	printf ("k1 res <%s> <%s>\n", k1, res);

	ht_findkey (ht2, k2, strlen(k2)+1, &res, &lres);
	printf ("k2 res <%s> <%s>\n", k2, res);

	/*  Walk first list  */
	ht_initwalk (ht1);
	while (e=ht_getnext(ht1)) {
		printf ("key data <%s> <%s>\n", e->key, e->data);
	}

	/*  Free lists  */
	ht_free (ht1);
	ht_free (ht2);

	/*  Read new list from arbitrary text file "test.in"  */
	ht1 = ht_init(10000,0);
	infile = fopen ("test.in", "r");
	if (NULL==infile) {
		printf ("Cannot open file \"test.in\" for example data.\n");
		return 0;
	}
	while (fgets(buffer,256,infile)) {
		sscanf(buffer, "%s %s",&bkey,&bdata);
		printf ("<%s> <%s>\n", bkey, bdata);
		ht_storekey (ht1, bkey, strlen(bkey)+1, bdata, strlen(bdata)+1);
	}
	fclose(infile);

	/*  Walk list  */
	ht_initwalk (ht1);
	while (e=ht_getnext(ht1)) {
		printf ("key data <%s> <%s>\n", e->key, e->data);
	}


	/*  Free list  */
	ht_free(ht1);


	return 0;

}
#endif
