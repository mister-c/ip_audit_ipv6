/*
------------------------------------------------------------------------
Includes
------------------------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/
#define MAX_COL 256
#define NSTR    256
#define IPLEN    16

/*
------------------------------------------------------------------------
Debug macros
------------------------------------------------------------------------
*/
#define WRITEMSG \
  printf ("File %s line %d\n", __FILE__, __LINE__); \
  fflush(stdout);

#define WRITETXT(txt) \
   printf ("File %s line %d: ** %s **\n", __FILE__, __LINE__, (txt));

#define WRITEVAR(VAL,FMT) \
		   printf ("File %s line %d: ", __FILE__, __LINE__); \
		   printf ("%s=",#VAL); printf (#FMT, VAL); printf ("\n"); \
		   fflush(stdout);

/*
------------------------------------------------------------------------
Global variables
------------------------------------------------------------------------
*/
extern int errno;

/*
------------------------------------------------------------------------
Modules variables
------------------------------------------------------------------------
*/
int debug_m = 0;

/*
------------------------------------------------------------------------
Prototypes
------------------------------------------------------------------------
*/
int   get_fields     (char *s, char **fptr, int);
int   is_whitespace  (int c);
void  parse_ip_range (char *arg_in, char (**iplist)[IPLEN], int *niplist);
int   in_iprange     (char *, char (*iplist)[IPLEN], int niplist);
int   str2ip         (char *ipstr);
void  ip2str         (int ip, char[IPLEN]);
void  ip2ipf         (char *ip, char ipf[IPLEN]);
int   str2mask       (char *ipstr);
void  Print_Usage    (void);

/*
------------------------------------------------------------------------
Main
------------------------------------------------------------------------
*/
int main (int argc, char *argv[]) {
	int  n_local_iplist = 0;
	int n_remote_iplist = 0;
	char (* local_iplist)[IPLEN] = NULL;
	char (*remote_iplist)[IPLEN] = NULL;
	int nfield;
	char *fptr[MAX_COL];
	int  loc0, loc1;
	int  rem0, rem1;
	char buffer[NSTR];
	char buffer2[NSTR];
	int  nbuffer;
	FILE *fin;
	int  openfile = 0;

	if (argc>1 && 
			( !strcmp("-h",argv[1]) || !strcmp("--help",argv[1]) )
		)
	{
		Print_Usage();
		return 1;
	}


	if (argc>1) {
		if (!strcmp("-",argv[1])) {
			fin = stdin;
		} else {
			fin = fopen(argv[1],"rt");
			if (NULL==fin) {
				fprintf (stderr, "ERROR:  Cannot open input file\n");
				return 1;
			}
		}
	} else {
		fin = stdin;
	}


	/*  Read ipaudit output from standard input and re-order ip data  */
   while (NULL!=fgets(buffer,NSTR,fin)) {

		/*  Skip comments  */
		if (buffer[0]=='#') continue;

		/*  Break into fields  */
		nfield = get_fields (buffer, fptr, 7);

		/*  Print fields 1,2,6,7,6+7  */
		printf ("%s %s %s %s %d\n",
				fptr[0],
				fptr[1],
				fptr[5],
				fptr[6],
				atoi(fptr[5])+atoi(fptr[6])
				);
	}

	/*  Close file  */
	if (argc>1)
		fclose (fin);
}



/*
------------------------------------------------------------------------
Local functions
------------------------------------------------------------------------
*/

int get_fields (char *s, char **fptr, int max_field) {
	int nfield=0;

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
	return nfield;
}


void Print_Usage (void) {
printf ("\ncalcbytes [file]\n");
printf ("\nConvert ipaudit data file from format of\n");
printf ("Reduce ipaudit data file records from\n");
printf ("Remove fields from ipaudit data file records so that\n");
printf ("following format\n");
printf ("   ip1 ip2 protocol port1 port2 incb outb inp outp firsttime  ...\n");
printf ("becomes\n");
printf ("   ip1 ip2 incb outb incb+outb\n\n");
printf ("This is useful for some ipaudit reports.\n\n");
}
