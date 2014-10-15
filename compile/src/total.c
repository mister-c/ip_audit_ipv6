/*
------------------------------------------------------------------------
History
------------------------------------------------------------------------
*/
/*
Jan 23, 2000
	Started
Oct 19, 2001
	Added Queue option
*/

/*

------------------------------------------------------------------------
Compile Switches
------------------------------------------------------------------------
*/
#define PARSE_COLUMN
#define USE_SORT
#define GET_DATA_COL

/*
------------------------------------------------------------------------
Usage
------------------------------------------------------------------------
*/
#define VERSION_STR " Version 0.95"
char *Usage_m[] = {
"",
"   total -dmqsvFN <key-col> <data-col> <file>",
"",
"     -d     Debug",
"     -f M   Print first M records (must also use sort option)",
"     -q N   Store at most N records, printing overflow as they're deleted",
"     -s I[r][,J[r][,...]]",
"            Sort records by columns I,J,..; in reverse order if 'r'",
"     -v     Print version info and exit",
"     -F c   Use character c as field delimiter",
"     -N H   Use H number of slots in hash table (-v option prints default)",
"",
"   Read text data <file>.  Each line contains a record consisting",
"   of space delimited fields, some of which are numeric.  Use",
"   <key-col> (comma delimited list of columns starting at 1, or '-'",
"   for no key) as record keys, and for each unique set of record",
"   keys calculate the column values requested in <data-col>.",
"",
"   <key-col>  comma delimited list of column numbers OR just '-'",
"              to indicate no keys, this groups all file records together.",
"   <data-col> comma delimited list of column numbers follow by",
"              an optional character s (sum - the default), a (average),",
"              d (standard deviation), or e (error in average).  Or instead ",
"              of a column number, the letter, 'n' to indicate count the",
"              number of records.",
"",
"   Examples:",
"",
"     Input file:    burt dog  10 5",
"                    burt fish  1 1",
"                    bill dog   2 2",
"                    burt dog   5 5",
"                    bill fish  3 1",
"",
"     Command:       total 1,2 3,4 input.fil",
"",
"     Output:        burt dog  15 10",
"                    burt fish  1  1",
"                    bill dog   2  2",
"                    bill fish  3  1",
"",
"     Command:       total 2 4,3,n input.fil",
"",
"     Output:        dog  12 17 3",
"                    fish  2  4 2",
"",
"     Command:       total - n input.fil",
"                    5",
"",
VERSION_STR,
0
};


						 
/*
------------------------------------------------------------------------
Include files
------------------------------------------------------------------------
*/
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include "hash.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
------------------------------------------------------------------------
DEFINES
------------------------------------------------------------------------
*/
#define MAX_COL 256
#define NSTR    4192

#define U_CHAR unsigned char

/*  Number of slots in hash table  */
#define N_HASH_SLOTS  500000

/*  Constant to denote unknown action  */
#define UNKNOWN_ACTION -1



/*
------------------------------------------------------------------------
Debugging Macros
------------------------------------------------------------------------
*/
#define WRITETXT(TXT) \
	printf ("FILE %s LINE %i: \"%s\"\n", __FILE__, __LINE__, TXT); \
	fflush (stdin);

#define WRITEMSG \
	printf ("In file %s at line %i.\n", __FILE__, __LINE__); \
	fflush (stdin);

#define WRITEVAR(VAR_NAME,VAR_TYPE) \
		printf ("FILE %s LINE %i: ", __FILE__, __LINE__); \
		printf ("%s <", #VAR_NAME); \
		printf (#VAR_TYPE, (VAR_NAME) ); \
		printf (">\n"); \
		fflush (stdin); 


/*
------------------------------------------------------------------------
Extern variables
------------------------------------------------------------------------
*/
/*  used by getop() function  */
extern char *optarg;

/*
------------------------------------------------------------------------
File variables
------------------------------------------------------------------------
*/
char *comment_char_m = "#";
int  debug_m = 0;
int  *sort_ord_m=NULL;
int  *sort_col_m=NULL;
int  nsort_col_m=0;

/*  Elements data_col_m[i], data_action_m[i] store the i'th
 *  output column specifictions entered by the user.
 */
int data_col_m[MAX_COL],   data_action_m[MAX_COL];

/*  Elements proc_col_m[i], proc_action_ms[i] store a unique
 *  combination of input data column and action (sum, min, max, etc)
 *  on that column.  A input single column n might appear in two
 *  different elements of proc_col_m[] if there are two actions done
 *  on that input column.
 */
int proc_col_m[2*MAX_COL], proc_action_m[2*MAX_COL];
int ndata_m, nproc_m;



/*
------------------------------------------------------------------------
Local Function Prototypes
------------------------------------------------------------------------
*/
int is_whitespace(int);
int is_comment(char *);
int find_action_col (int *, int *, int, int, int);
int get_fields (char *, char *[],int, char);
void prformat(double);
int isnumber (char *);
void print_key    (helem_t  *, int *, int *, int *, int *, int, int);
void walk_history (htable_t *, int *, int *, int *, int *, int, int);
void parse_column (char *, int *, int *, int *, char);
int dcmp (const void *aptr, const void *bptr);
double get_data_col ( helem_t *, int);
int get_max_index ( helem_t **, int, int (*cmp)(const void *, const void *));



/*
------------------------------------------------------------------------
Main function
------------------------------------------------------------------------
*/
main (int argc, char *argv[]) {
	int arg;
	int nkey, nfield;
	int nrdata;
	int ikey, idata, iproc;
	int lastchr;
	int key_col[MAX_COL]; 
	int i;
	char *keystr, *datastr, *ptr;
	char buffer [NSTR];
	double *databuf = NULL;
	double *rdata   = NULL;
	double  val;
	char keybuff[NSTR];
	char *fptr[MAX_COL];
	long   cnt;
	htable_t *ht = NULL;
	helem_t  *t        = NULL;
	FILE *fin;
	int res;
	double avg;
	int max_col;
	int optchar;
	int nhashslots = N_HASH_SLOTS;
	int max_queue_length=0;
	int max_output=0;
	int use_sort  =0;
	int use_top_sort = 0;
	helem_t **index = NULL;
	char field_sep[2] = " ";
	int max_index;

	/*  Read command line options  */
	while (-1 != (optchar=getopt(argc,argv,"F:N:df:q:s:v"))) {
		switch (optchar) {
			case '?':
			return 1;
		/*  Debugging option  */
		case 'd':
			debug_m = 1;
			printf ("Debugging mode is on\n");
			break;
		case 'v':
			printf ("Version %s (compiled %s)\n", VERSION_STR,__DATE__);
			printf ("Default number of hash slots = %d\n", N_HASH_SLOTS);
			return 0;
			break;
		case 'N':
			nhashslots = atoi(optarg);
			if (nhashslots<1) {
				printf (
				"ERROR: Number of hash slots (-N%d) must be one or greater\n", 
				nhashslots);
				exit(1);
			}
			break;
		case 'F':
			field_sep[0] = optarg[0];
			break;
		case 'q':
			max_queue_length = atoi(optarg);
			if (max_queue_length<0) max_queue_length=0;
			break;
		case 'f':
			max_output = atoi(optarg);
			break;
		case 's':
			use_sort   = 1;
			sort_col_m = (int *) calloc(MAX_COL, sizeof(int));
			sort_ord_m = (int *) calloc(MAX_COL, sizeof(int));
			parse_column (optarg, sort_col_m, sort_ord_m, &nsort_col_m, 'f');
			break;
		default:
			return 1;
		}
	}

	/*  Print Usage  */
	if (argc<4) {
		char **ptr = Usage_m;
		printf ("%s\n", *ptr);
		while (*ptr) {
			printf ("%s\n", *(ptr++));
		}
		return 0;
	}

	
	/*  Parse key column arguement : a '-' means no key  */
	nkey=0;
	keystr = strdup (argv[optind++]);
	if (strcmp("-",keystr)) {
		ptr=strtok(keystr,",");
		while (ptr) {
			if (! isnumber(ptr) ) {
				printf ("ERROR: Key column argument is not numeric\n");
				return 1;
			}
			if (0>(val=atoi(ptr)-1)) {
				printf ("ERROR: Key column argument is 0\n");
				return 1;
			}
			key_col[nkey++] = atoi(ptr)-1;
			ptr = strtok(NULL,",");
		}
	}

	/*  Parse data column argument  */
	datastr = strdup (argv[optind++]);
	parse_column (datastr, data_col_m, data_action_m, &ndata_m, 's');

	/*  Determine actual data processes from requested data  */   
	nproc_m=0;
	proc_col_m   [nproc_m  ] =   0;
	proc_action_m[nproc_m++] = 'n';
	for (i=0;i<ndata_m;i++) {

		/*  Check for duplicate action  */
		if (UNKNOWN_ACTION != find_action_col
				(proc_col_m, proc_action_m, data_col_m[i], data_action_m[i],nproc_m) )
			continue;

		/*  Print error if too many requested */
		if (ndata_m>2*MAX_COL) {
			fprintf (stderr, 
				"ERROR:  To many data actions specified.  Max allowed is %d\n", 
				2*MAX_COL);
			exit (1);
		}

		/*  Save data column action in process  */
		switch (data_action_m[i]) {
			/*  Field counts happens automatically  */
			case 'n':
				break;
			/*  Standard deviation requires summation also  */
			case 'd':
			case 'e':
				proc_action_m[nproc_m  ] = data_action_m[i];
				proc_col_m   [nproc_m++] = data_col_m[i];
				/*  Include summation for this column if not already present  */
				if (UNKNOWN_ACTION == find_action_col 
						(proc_col_m, proc_action_m, data_col_m[i], 's', nproc_m) ) {
					proc_action_m[nproc_m  ] = 's';
					proc_col_m   [nproc_m++] = data_col_m[i];
				}
				break;
			/*  'Simple' processes */
			case 'm':  /*  Minimum  */
			case 'x':  /*  Maximum  */
			case 'a':  /*  Average  */
			case 's':  /*  Sum      */
			case 'f':  /*  First    */
			case 'l':  /*  Last     */
				proc_action_m[nproc_m  ] = data_action_m[i];
				proc_col_m   [nproc_m++] = data_col_m[i];
				break;
		}
	}


	/*  Open file  (use stdin if file "-")  */
	if (!strcmp("-",argv[optind])) {
		fin = stdin;
	} else {
		fin = fopen (argv[optind], "rt");
		if (NULL==fin) {
			printf ("ERROR:  Cannot open input file <%s>\n", argv[optind]);
			return 1;
		}
	}

	/*  Find maximum key,data column  */
	max_col=0;
	for (idata=0;idata<ndata_m;idata++) 
		if (max_col<data_col_m[idata]) max_col = data_col_m[idata];
	for (ikey=0;ikey<nkey;ikey++) 
		if (max_col<key_col[ikey]) max_col = key_col[ikey];
	

	/*  Allocate data storage  */
	databuf  = (double *) calloc (nproc_m, sizeof(double));

	/*  Initialize hash table  */
	ht = ht_init(nhashslots, max_queue_length ? HT_HISTORY : 0);

	/*  Read file  */
	while (NULL!=fgets(buffer,NSTR,fin)) {
		buffer[strlen(buffer)-1] = '\0';
		if (is_comment(buffer))  continue;
		nfield = get_fields (buffer, fptr, max_col+1, field_sep[0]);
		if (max_col>=nfield) continue;

		/*  Form key  */
		if (nkey)
			strcpy (keybuff, fptr[key_col[0]]);
		else
			keybuff[0]='\0';
		for (ikey=1;ikey<nkey;ikey++) {
			strcat (keybuff, field_sep);
			strcat (keybuff, fptr[key_col[ikey]]);
		}

		/*  Lookup key, process entry  */
		if ( 
			(t=ht_findelem (ht,(U_CHAR *)&keybuff ,strlen(keybuff)+1))
			) {
			rdata = (double *) t->data;
			rdata[0] = rdata[0] + 1;
			for (iproc=1;iproc<nproc_m;iproc++) {
				val = atof(fptr[proc_col_m[iproc]]);
				switch (proc_action_m[iproc]) {
					case 'a':
					case 's':
						rdata[iproc] += val;
						break;
					case 'd':
					case 'e':
						rdata[iproc] += val*val;
						break;
					case 'n':
						rdata[iproc] = rdata[iproc] + 1;
						break;
					case 'm':
						if (val<rdata[iproc]) rdata[iproc] = val;
						break;
					case 'x':
						if (val>rdata[iproc]) rdata[iproc] = val;
						break;
					/*  'f' means looking for first entry, its already there */
					case 'f':
						break;
					/*  'l' -> last entry  */
					case 'l':
						rdata[iproc] = val;
						break;
				}
			}
			/*  Make current key the newest  */
			ht_makenewest (ht, t);
			
		/*  No key found, create new entry  */
		} else {
			databuf[0] = 1;
			for (iproc=1;iproc<nproc_m;iproc++) {
				val = atof(fptr[proc_col_m[iproc]]);
				switch (proc_action_m[iproc]) {
					case 'a':
					case 's':
						databuf[iproc] = val;
						break;
					case 'd':
					case 'e':
						databuf[iproc] = val*val;
						break;
					case 'n':
						databuf[iproc] = 1;
						break;
					case 'm':
					case 'x':
					case 'f':
					case 'l':
						databuf[iproc] = val;
						break;
				}
			}
			ht_storekey (ht, (U_CHAR *) &keybuff, strlen(keybuff)+1, 
				(U_CHAR *) databuf, nproc_m*sizeof(databuf[0]));

		}  /* add new entry  */

		/*  Too many keys - print and remove oldest  */
		if (max_queue_length && ht_getcount(ht)>max_queue_length) {
			t = ht_getoldest(ht);
			print_key (t,data_col_m,data_action_m,proc_col_m,proc_action_m,ndata_m,nproc_m);
			ht_freeelem(ht,t);
		}

	}   /*  read file  */
		
	fclose(fin);

	/*  If no elements, then suppress sort  */
	if (ht_getcount(ht)==0) {
		use_sort = 0;
		max_output = 0;
	}

	/*  If sorting and printing only top count, 
	 *  choose 'top-only sort' over 'straight sort'
	 *  if number of top elements is less than 1/3 total
	 *  (1/3 is a very rough efficiany estimate, feel free
	 *  to change this if you have a better idea).
	 */
	if (use_sort && max_output && max_output<ht_getcount(ht)/3)
		use_top_sort = 1;

	/*  Print results in sorted order of data, top max_output only  */
	if (use_top_sort) {

		/*  Allocate index storage for number of top data  */
		index = (helem_t **) calloc(max_output, sizeof(helem_t *));
   	if (NULL==index) {
   		printf ("ERROR:  Cannot allocate memory for top_sort index\n");
   		return 1;
   	}

		/*  Place the first max_output elements into index  */
		ht_initwalk(ht);
		for (i=0;i<max_output;i++) {
			index[i] = ht_getnext(ht);
		}

		/*  Read through rest of list comparing with max_index  */
		max_index = get_max_index(index,max_output,dcmp);
		while (t = ht_getnext(ht)) {
			if (dcmp(index+max_index,&t)>0) {
				index[max_index] = t;
				max_index = get_max_index(index,max_output,dcmp);
			}
		}

		/*  Now have pointers to top max_output elements 
		 *  next sort and print
		 */
   	qsort (index, max_output, sizeof(helem_t*), dcmp);
   	for (i=0;i<max_output;i++) {
   		t = index[i];
   		print_key (t,data_col_m,data_action_m,proc_col_m,
					proc_action_m,ndata_m,nproc_m);
   	}
   	free (index);


	/*  Print results in sorted order of data  */
	} else if (use_sort) {
   	ht_initwalk(ht);
   	index = (helem_t **) calloc (ht_getcount(ht), sizeof(helem_t *));
   	if (NULL==index) {
   		printf ("ERROR:  Cannot allocate memory for sort index\n");
   		return 1;
   	}
   	i=ht_getcount(ht);
   	do {
   		i--;
   		index[i] = ht_getnext(ht);
   	} while (i);
   	qsort (index, ht_getcount(ht), sizeof(helem_t*), dcmp);
   	for (i=0;i<ht_getcount(ht);i++) {
   		t = index[i];
   		if (max_output && i>=max_output)
   			break;
   		print_key (t,data_col_m,data_action_m,proc_col_m,
					proc_action_m,ndata_m,nproc_m);
   	}
   	free (index);

	/*  Print results without sorting  */
   } else {
   
   	/*  Write results  */
   	ht_initwalk (ht);
   	while ((t=ht_getnext(ht))) {
   		/*  Print key and data  */
   		print_key (t,data_col_m,data_action_m,proc_col_m,
					proc_action_m,ndata_m,nproc_m);
   	}
   
   }

	/*  Print debug information if asked  */
	if (debug_m) ht_debuginfo(ht);
		
	/*  Don't bother freeing table, it takes alot of time cause we free each node individually,
	 *  just let OS free it up, it goes *much* faster
	 */
	/*  Free table  */
	/*
	ht_free (ht);
	*/

	return 0;
}
	


/*
------------------------------------------------------------------------
Local functions
------------------------------------------------------------------------
*/
int is_delimiter(int c, char *delimiter) {
	return (NULL!=strchr(delimiter,c));
}

int is_whitespace(int c) {
	return (NULL!=strchr(" \t\n\r",c));
}

int is_comment(char *s) {
	while (*s && is_whitespace(*s)) s++;
	return (*s==comment_char_m[0]);
}

/*
Fill fptr() array with pointers to tokens in string,
return number of tokens found
*/
#if 0
int get_fields (char *s, char **fptr) {
	static char *delimiter = " \t\r";
	int nfield = 0;

	/*  Skip leading whitespace  */
	while (*s && is_delimiter(*s,delimiter)) s++;
	/*  Find tokens  */
	while (*s && nfield<MAX_COL) {
		fptr[nfield++] = s;
		/*  Find first delimiter  */
		while (*s && !is_delimiter(*s,delimiter))  s++;
		/*  Make first white space string terminator */
		if (*s)  *s++ = '\0';
		/*  Find last delimiter */
		while (*s &&  is_delimiter(*s,delimiter))  s++;
	}
	return nfield;
}
#endif
int get_fields (char *s, char **fptr, int max_field, char field_sep) {
	int nfield=0;

	/*  Fields separated by one or more blanks - leading blanks ignored  */
	if (field_sep==' ') {

      /*  Skip leading whitespace  */
      while (*s==' ' || *s=='\t') s++;
      /*  Find tokens  */
      while (*s && nfield<max_field) {
         fptr[nfield++] = s;
         /*  Find first whitespace  */
   		while (*s!=' ' && *s && *s!='\t')  s++;
   		/*  Make first white space string terminator */
   		if (*s)  *s++ = '\0';
   		/*  Find last whitespace */
   		while (*s==' ' || *s=='\t')  s++;
   	}

	/*  Fields separated by single field separator  */
	} else {
		
      /*  Find tokens  */
      while (*s && nfield<max_field) {
         fptr[nfield++] = s;
         /*  Find next field separator  */
   		while (*s && *s!=field_sep)  s++;
   		/*  Make field separator string terminator */
   		if (*s)  *s++ = '\0';
   	}

	}

	return nfield;
}


/*  Return list_col[] index which is result of 'action' on
 *  output data column 'col'
 */ 
int find_action_col 
(int *list_col, int *list_action, int col, int action, int nlist) { 
	int i;
	for (i=0;i<nlist;i++) {
		if (list_col[i]==col && list_action[i]==action) 
			return i;
	}
	return UNKNOWN_ACTION;
}


/*  Print double in integer format if integer  */
void prformat(double d) {
	if (rint(d)==d)  printf (" %.0lf", d);
	else             printf (" %e",    d);
}


/*  Return 0,1 if string non-numeric,numeric */
int isnumber (char *str) {
	while (*str) {
		if (*str<'0'  || *str>'9')
			return 0;
		str++;
	}
	return 1;
}


/*  Print key and data for this hash element  */
void print_key (
helem_t *t, 
int *data_col_m, 
int *data_action_m, 
int *proc_col_m, 
int *proc_action_m,
int ndata_m,
int nproc_m) {
	int    idata;
	double val;

	/*  No element - print blank line  */
	if (t==NULL) {
		printf ("\n");
		return;
	}

	/*  Print key  */
	printf ("%s", t->key);
	/*  Print requested fields  */
	for (idata=0;idata<ndata_m;idata++) {
		val = get_data_col(t,idata);
		prformat (val);
	}
	printf ("\n");
}


/*  Given hash element and output data column description
 *  return output double value
 */
double get_data_col (
helem_t *t, 
int idata) {
	double *rdata = (double *) t->data;
	double avg;
	int    isum;
	int    iproc;

	/*  If data action is 'n', just need first element  */
	if (data_action_m[idata]=='n' || data_action_m[idata]=='-') {
		return rdata[0];
	}

	/*  Other actions  */
	iproc = find_action_col 
		(proc_col_m, proc_action_m, data_col_m[idata], data_action_m[idata], nproc_m);
	switch (data_action_m[idata]) {
		/*  Print sum, min, max as is  */
		case 's':
		case 'm':
		case 'x':
		case 'f':
		case 'l':
			return rdata[iproc];
			break;
		/*  Calculate average  */
		case 'a':
			if (rdata[0]==0) return 0.0;
			else             return rdata[iproc]/rdata[0];
			break;
		/*  Calculate standard deviation or error (std.dev./sqrt(n))  */
		case 'd':
		case 'e':
			if (rdata[0]==0) return 0.0;
			else {
				/*  Find corresponding sum value  */
				isum = find_action_col
					(proc_col_m, proc_action_m, data_col_m[idata], 's', nproc_m);
				if (isum==-1) {
					fprintf (stderr, "INTERNAL ERROR:  No sum stored for");
					fprintf (stderr, " standard deviation calculation\n");
					exit(2);
				}
				avg = rdata[isum]/rdata[0];
				if (data_action_m[idata] == 'e')  {
					return sqrt((rdata[iproc]/rdata[0]-avg*avg)/rdata[0]);
				}
				else
					return sqrt( rdata[iproc]/rdata[0]-avg*avg          );
			}
			break;
	}  /* end of data_action_m[] switch  */
}


void walk_history (
htable_t *ht, 
int *data_col_m, 
int *data_action_m, 
int *proc_col_m, 
int *proc_action_m,
int ndata_m,
int nproc_m) {
		  /*test*/
		  helem_t *e = ht_getoldest(ht);
		  while (e) {
			  print_key (e,data_col_m,data_action_m,proc_col_m,proc_action_m,ndata_m,nproc_m);
			  e = (helem_t *) e->newer;
		  }
}



/*  Callback function called by qsort() to order output records  */
int dcmp (const void *aptr, const void *bptr) {
	helem_t *a = * ( (helem_t **) aptr );
	helem_t *b = * ( (helem_t **) bptr );
	double diff;
	int i,j,idiff;

	for (i=0;i<nsort_col_m;i++) {
		j = sort_col_m[i];
		diff = get_data_col(a,j) - get_data_col(b,j);
		if (diff==0.0) 
			continue;
		idiff = diff>0 ? 1 : -1;
		if (sort_ord_m[i]=='r')
			return -idiff;
		else
			return idiff;
	}
	return 0;
}


/*  
Parse data column argument 

arg               string being parsed for data column and actions
data_col_m[]      column indices returned
data_action_m[]   action codes (a,m,n,s,x) returned
ndata             number of index,action pairs returned
def_char          default action code

Note that legal action code 'n' will result in column number -1.
Need to take precautions.

*/
void parse_column
(char *arg, int *data_col, int *data_action, int *ndata, char def_char) {
	char *ptr;
	char lastchr;
	int  col;
	*ndata=0;
	ptr=strtok(arg,",");
	while (ptr) {
		/*  Print error if too many data columns  */
		if (*ndata>MAX_COL) {
			fprintf (stderr,
				"ERROR:  To many data columns specified.  Max allowed is %d\n", 
				MAX_COL);
			exit (1);
		}
		/*  Get trailing character if a,m,n,s,x  */
		lastchr = ptr[strlen(ptr)-1];
		if (!strchr("0123456789", lastchr)) {
			data_action[*ndata] = lastchr;
			ptr[strlen(ptr)-1] = '\0';
		} else {
			data_action[*ndata] = def_char;
		}
		/*  Read column number for this data item  */
		col = atoi(ptr)-1;
		data_col[(*ndata)++] = col;
		ptr=strtok(NULL,",");
	}
}




/*  Search list of pointers for smallest element  */
int get_max_index (
		helem_t **index, 
		int n,
		int (*cmp)(const void *, const void *))
{
	int max = 0;
	int j;
	for (j=1;j<n;j++) {
		if ( cmp( index+max, index+j )<0 ) {
			max = j;
		}
	}
	return max;
}
