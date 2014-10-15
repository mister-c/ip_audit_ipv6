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
	int nfield;
	char *fptr[MAX_COL];
	char buffer[NSTR];
	int  nbuffer;
	FILE *fin;

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

		/*  Strip newline  */
		if ( 0<(nbuffer = strlen(buffer)-1) )
			buffer[nbuffer] = '\0';


		/*  Break into fields  */
		nfield = get_fields (buffer, fptr, 3);

		/*  Print fields 1,2  */
		if (!strcmp(fptr[2],"0"))
			printf ("%s %s \n", fptr[0], fptr[1]);
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
printf ("\n   lookforzero [file]\n\n");
printf ("   Reads text file and prints first two blank-delmieted\n");
printf ("   fields if third field is \"0\".\n\n");
printf ("   This is useful for some ipaudit reports.\n\n");
}
