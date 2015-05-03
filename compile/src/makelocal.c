/*
------------------------------------------------------------------------
Includes
------------------------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
#define IPLEN4    16
#define IPLEN6    40 
//8 groups of four characters each seperated by one of 7 colons terminaed
// with a \0 = 40 characters
#define IPLEN6_BIN    16


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
Macros
------------------------------------------------------------------------
*/
#define IS_REMOTE(fptr)  ( ! ( \
			      in_iprange ((fptr),  local_iplist_m,  n_local_iplist_m) || \
			      in_iprange6 ((fptr), local_iplist6_m, n_local_iplist6_m) || \
   n_other_iplist_m && \
			      in_iprange ((fptr), other_iplist_m,  n_other_iplist_m)   ) )

   


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

int  n_local_iplist_m = 0;
int  n_local_iplist6_m = 0;
int  n_other_iplist_m = 0;
int  n_other_iplist6_m = 0;
char (*local_iplist_m)[IPLEN4] = NULL;
char (*local_iplist6_m)[IPLEN6] = NULL;
char (*other_iplist_m)[IPLEN4] = NULL;
char (*other_iplist6_m)[IPLEN6] = NULL;

/*
------------------------------------------------------------------------
Prototypes
------------------------------------------------------------------------
*/
int   get_fields     (char *s, char **fptr, int);
int   is_whitespace  (int c);
void  parse_ip_range (char *arg_in, char (**iplist4)[IPLEN4], char (**iplist6)[IPLEN6],
		      int *niplist4, int *niplist6); 
int   get_range_code (char *ip);
int   in_iprange     (char *, char (*iplist)[IPLEN4], int niplist4);
int   in_iprange6    (char *, char (*iplist)[IPLEN6], int niplist6);
int   str2ip         (char *ipstr);
void  str2ip6        (char *ipstr, char buffer[IPLEN6_BIN]);
void  ip2str         (int ip, char[IPLEN4]);
void  ip2str6        (char int_buff[IPLEN6_BIN], char str_buff[IPLEN6]);
void  ip2ipf         (char *ip, char ipf[IPLEN4]);
void  ip2ipf6         (char *ip, char ipf[IPLEN6]);
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
   int  loc0, loc1;
   int  rem0, rem1;
   char buffer[NSTR];
   char buffer2[NSTR];
   int  nbuffer;
   FILE *fin;
   char *filter = NULL;
   char optchar;
   int  do_traffic_summary=0;
   int  code0, code1;
   double incb, outb, incp, outp;
   double 
      connections = 0, 
      packets = 0, 
      bytes = 0, 
      incoming = 0, 
      outgoing = 0, 
      external = 0, 
      internal = 0, 
      other = 0;

   /*  Read options  */
   while (-1 != (optchar=getopt(argc,argv,"sf:"))) {
      switch (optchar) {
         case 'f':
            filter = strdup(optarg);
            break;
         case 's':
            do_traffic_summary = 1;
            break;
      }
   }


   if (argc==optind) {
      Print_Usage();
      return 1;
   }

   /*  First argument is local net  */
   parse_ip_range (argv[optind], &local_iplist_m, &local_iplist6_m,
		   &n_local_iplist_m, &n_local_iplist6_m);

   /*  Second argument (if present) is other net
    *  '-' means any non-local is considered other  
    *  */
   if (argc>optind+1 && strcmp("-",argv[optind])) {
     parse_ip_range(argv[optind+1], &other_iplist_m, &other_iplist6_m, &n_other_iplist_m, &n_other_iplist6_m);
   }
   

   if (argc>optind+2) {
      if (!strcmp("-",argv[optind+2])) {
         fin = stdin;
      } else {
         fin = fopen(argv[optind+2],"rt");
         if (NULL==fin) {
            fprintf (stderr, "ERROR:  Cannot open input file\n");
            return 1;
         }
      }
   } else
      fin = stdin;

   /*  Read ipaudit output from standard input and re-order ip data  */
   while (NULL!=fgets(buffer,NSTR,fin)) {
      /*  Skip comments  */
      if (buffer[0]=='#') continue;

      /*  Remove trailing \n  */
      nbuffer = strlen(buffer)-1;
      buffer[nbuffer] = '\0';
      strncpy(buffer2,buffer,nbuffer+1);

      /*  Do summary  */
      if (do_traffic_summary) {
         nfield = get_fields (buffer, fptr, 9);
         if (nfield<9) continue;
         code0 = get_range_code (fptr[0]);
         code1 = get_range_code (fptr[1]);
         incb  = atof (fptr[5]);
         outb  = atof (fptr[6]);
         incp  = atof (fptr[7]);
         outp  = atof (fptr[8]);
         connections++;
         packets += incp + outp;
         bytes   += incb + outb;
         if        (code0=='L' && code1=='R') {
            incoming += incb;
            outgoing += outb;
         } else if (code0=='R' && code1=='L') {
            incoming += outb;
            outgoing += incb;
         } else if (code0=='L' && code1=='L') {
            internal += incb + outb;
         } else if (code0=='R' && code1=='R') {
            external += incb + outb;
         } else {
            other    += incb + outb;
         }
         continue;
      }

      /*  Break into fields  */
      nfield = get_fields (buffer, fptr, 2);

      /* TODO Check if this works???? */

      /*  Print if first field is local ip  */
      if (filter && !strcmp(filter,"l")) {
         loc0 = in_iprange (fptr[0], local_iplist_m,  n_local_iplist_m);
         if (loc0) 
            printf ("%s\n", buffer2);
         continue;
      }

      /*  Repeat for ipv6  */
      if (filter && !strcmp(filter,"l")) {
         loc0 = in_iprange6 (fptr[0], local_iplist6_m,  n_local_iplist6_m);
         if (loc0) 
            printf ("%s\n", buffer2);
         continue;
      }

      /*  Print if first two fields are local ip  */
      if (filter && !strcmp(filter,"ll")) {
         loc0 = in_iprange (fptr[0], local_iplist_m,  n_local_iplist_m);
         loc1 = in_iprange (fptr[1], local_iplist_m,  n_local_iplist_m);
         if (loc0 && loc1)
            printf ("%s\n", buffer2);
         continue;
      }

      /*  Repeat for ipv6  */
      if (filter && !strcmp(filter,"ll")) {
         loc0 = in_iprange6 (fptr[0], local_iplist6_m,  n_local_iplist6_m);
         loc1 = in_iprange6 (fptr[1], local_iplist6_m,  n_local_iplist6_m);
         if (loc0 && loc1)
            printf ("%s\n", buffer2);
         continue;
      }

      /*  Print if first field is other ip  */
      if (filter && !strcmp(filter,"r")) {
         rem0 = IS_REMOTE(fptr[0]);
         if (rem0) 
            printf ("%s\n", buffer2);
         continue;
      }

      /*  Print if first two fields are other ip  */
      if (filter && !strcmp(filter,"rr")) {
         rem0 = IS_REMOTE(fptr[0]);
         rem1 = IS_REMOTE(fptr[1]);
         if (rem0 && rem1)
            printf ("%s\n", buffer2);
         continue;
      }

      /*  Print if first two fields are local/other or other/local  */
      loc0 = in_iprange (fptr[0], local_iplist_m,  n_local_iplist_m) || in_iprange6 (fptr[0], local_iplist6_m,  n_local_iplist6_m);
      rem1 = IS_REMOTE  (fptr[1]);

      /*  Address already local/other  */
      if (loc0 && rem1) {
         printf ("%s\n", buffer2);

      /*  Address is other/local, so switch order */
      } else {
         loc1 = in_iprange (fptr[1], local_iplist_m, n_local_iplist_m) || in_iprange6 (fptr[1], local_iplist6_m,  n_local_iplist6_m);
	 /*DEBUG*/
         rem0 = IS_REMOTE  (fptr[0]);
         if (rem0 && loc1) {
            nfield = get_fields (buffer2, fptr, MAX_COL);
            /* do stuff  */
            printf ("%s %s %s %s %s %s %s %s %s %s %s %d %d\n",
                  fptr[1],
                  fptr[0],
                  fptr[2],
                  fptr[4],
                  fptr[3],
                  fptr[6],
                  fptr[5],
                  fptr[8],
                  fptr[7],
                  fptr[9],
                  fptr[10],
                  3-atoi(fptr[11]),
                  3-atoi(fptr[12])
                  );
         }
      }
      /*  Local/Local or Other/Other are rejected  */
   }

   /*  Write summary  */
   if (do_traffic_summary)

      printf ("%.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f %.0f\n",
         connections, 
         packets, 
         bytes, 
         incoming, 
         outgoing, 
         incoming+outgoing,
         internal, 
         external, 
         other);

   /*  Close file  */
   if (argc>2)
      fclose (fin);
}



/*
------------------------------------------------------------------------
Local functions
------------------------------------------------------------------------
*/
void parse_ip_range (char *arg_in, char (**iplist4)[IPLEN4], 
		     char (**iplist6)[IPLEN6], int *niplist4, int *niplist6) {
   char *arg_cpy = (char *) malloc (strlen(arg_in)+1);
   char *ipstr   = (char *) malloc (strlen(arg_in)+1);
   char *netstr  = (char *) malloc (strlen(arg_in)+1);
   char *maskstr = (char *) malloc (strlen(arg_in)+1);
   char *range1  = NULL;
   char *range2  = NULL;
   int  ip_vsn;
   int  nrange;
   int  mask;
   int  net;
   int  ip1, ip2;
   char ip6_1[IPLEN6_BIN];
   char ip6_2[IPLEN6_BIN];
   int  n4;
   int  n6;
   char *p1;
   int v1;

   *iplist4  = NULL;
   *iplist6  = NULL;
   *niplist4 =0;
   *niplist6 =0;

   /*  If no list (no string, blank string or string eq '-'
    *  then return null  */
   if (arg_in==NULL || *arg_in==0 || (!strcmp("-",arg_in)) )
      return;
      
   /*  Count number of ranges (equals number of : + 1 )  */
   p1 = arg_in;

   n4 = 0;
   n6 = 0;

   v1 = 4;

   while (*p1++) {
     if (*p1==':') v1 = 6;
     if (*p1=='.') v1 = 4;
     if (*p1==',' && v1 ==4) n4++;
     if (*p1==',' && v1 ==6) n6++;
   }
   if (v1 == 6){
     n6++;
   } else if (v1 == 4){
     n4++;
   }

   /*  allocate storage  */
   *iplist4 = (char (*)[IPLEN4]) malloc (2 * n4 * IPLEN4);
   *iplist6 = (char (*)[IPLEN6]) malloc (2 * n6 * IPLEN6);
   if (n4+n6==0) {
      *niplist4 = 0;
      *niplist6 = 0;
      return;
   }

   strcpy  (arg_cpy, arg_in);
   range2 = arg_cpy;

   /*  break string into separate ranges  */
   *niplist4 = 0;
   *niplist6 =0;
   while (NULL!=range2) {
      /*  Break arg into (1st range):(remaining ranges)  */
      range1 = range2;
      range2 = strchr(range1, ',');
      if (NULL!=range2) *range2++ = '\0';
      ip_vsn = 4;
      if(NULL!=strchr(range1, ':')){
	ip_vsn = 6;
      }

      /*  Look for range expressed as (lo ip)-(hi ip)  */
       if (2==sscanf (range1, "%[0-9abcdef.:]-%[0-9abcdef.:]", ipstr, netstr)) {
	 if(ip_vsn == 6){
	   str2ip6(ipstr, ip6_1);
	   str2ip6(netstr, ip6_2);
	 } else{
	   ip1 = str2ip(ipstr);
	   ip2 = str2ip(netstr);
	 }

      /*  break range into (ip)/(net) or (ip)/(mask)  */
       } else if (2==sscanf (range1, "%[0-9abcdef.:]/%[0-9abcdef.]", ipstr, netstr)) {

         /*  read ip address  */
	 if(ip_vsn == 6){
	   str2ip6(ipstr, ip6_1);
	 } else{
	   ip1 = str2ip(ipstr);
	 }

         /*  Second substr is a mask (255.225.255.0)  */
         if (strchr (netstr,'.')) {
            mask = str2ip (netstr);
            ip1 = ip1 &  mask;
            ip2 = ip1 | ~mask;

         /*  Second substr is a net size (24)  */
         } else {
            net = atoi(netstr);
            if (net<0) net=0;
            else if (net>128) net=128;

	    if(ip_vsn == 6){
	      /* TODO figure out how to fix this */
	      /* mask = 0xffffffff >> net;  */
	      return;
	    } else {
	      mask = 0xffffffff >> net;
	    }
            if (mask==-1) mask = 0;
            ip2 = ip1 | mask;
         }

      /*  Look for single ip address  */
      } else if (sscanf (range1, "%[0-9abcdef.:].%[0-9abcdef:].", ipstr, netstr)) {
	 if(ip_vsn == 6){
	   str2ip6 (ipstr, ip6_1);
	   str2ip6 (ipstr, ip6_2);
	   /* ip2 = ip1 | str2mask6(ipstr); */
	 } else{
	   ip1 = str2ip (ipstr);
	   ip2 = ip1 | str2mask(ipstr);
	 }

      /*  Bad input format  */
      } else {
         fprintf (stderr, 
               "ERROR:  Cannot read network range argument.\n");
         fprintf (stderr, 
               "  Program continues with using default network range.\n");
         *niplist4 = 0;
         if (NULL!=*iplist4) free (*iplist4);
         if (NULL!=*iplist6) free (*iplist6);
         return;
      }

      /* Store results  */
       if(ip_vsn == 6){
	 ip2str6 (ip6_1,(*iplist6)[(*niplist6)++]);
	 ip2str6 (ip6_2,(*iplist6)[(*niplist6)++]);
       } else {
	 ip2str (ip1,(*iplist4)[(*niplist4)++]);
	 ip2str (ip2,(*iplist4)[(*niplist4)++]);
       }
   }

   free (netstr);
   free (ipstr);
   free (arg_cpy);

   /*  Correct double counting of niplist  */
   *niplist4 /= 2;
   *niplist6 /= 2;
}


/*  Determine if ipaddresses is within one of the ranges in iplist  */
/*  If no range specified, then ip address *is* in range  */
int in_iprange (char *ip, char (*iplist)[IPLEN4], int niplist4) {
   int i;
   char ipf[IPLEN4];
   /* If we aren't checking for an ipv4 address then return false */
   if(NULL==strchr(ip, '.')){
     return 0;     
   }
   /*  No network list implies *all* ip addresses  */
   if (niplist4==0 || iplist==NULL || iplist[0]==NULL){
     return 1;
   }
   if (ip==NULL) return 0;
   ip2ipf(ip,ipf);
   for (i=0;i<2*niplist4;i+=2)  {
     if (strcmp(ipf,iplist[i])>=0 && strcmp(ipf,iplist[i+1])<=0){
	return 1;
     }
   }
   return 0;
}

/*  Determine if ipaddresses is within one of the ranges in iplist  */
/*  If no range specified, then ip address *is* in range  */
int in_iprange6 (char *ip, char (*iplist)[IPLEN6], int niplist6) {
   int i;
   char ipf[IPLEN6];
   /* If we aren't checking for an ipv4 address then return true */
   if(NULL==strchr(ip, ':')){
     return 0;
   }
   /*  No network list implies *all* ip addresses  */
   if (niplist6==0 || iplist==NULL || iplist[0]==NULL){
     return 1;
   } 
   if (ip==NULL) return 0;
   ip2ipf6(ip,ipf);
   for (i=0;i<2*niplist6;i+=2)  {
     if (strcmp(ipf,iplist[i])>=0 && strcmp(ipf,iplist[i+1])<=0){
	 return 1;
     }
   }
   return 0;
}


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

/*  Convert strings like "138.99.201.5" or "137.99.26" to int ipaddress  */
int str2ip (char *ipstr) {
   int ip[4];
   int i;
   int ipout=0;
   int n = sscanf (ipstr, "%d.%d.%d.%d", ip, ip+1, ip+2, ip+3);
   for (i=0;i<4;i++) {
      ipout = ipout<<8;
      if (i<n) ipout |= (ip[i] & 0xff);
   }
   return ipout;
}

void str2ip6 (char *ipstr, char buffer[IPLEN6_BIN]) {
   int ip[16];
   int i;
   int n = sscanf (ipstr, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		   ip, ip+1, ip+2, ip+3, ip+4, ip+5, ip+6, ip+7, ip+8,
		   ip+9, ip+10, ip+11, ip+12, ip+13, ip+14, ip+15, ip+16);
    for (i=0;i<16;i++) {
      buffer[i] = 0;
      if (i<n) buffer[i] |= (ip[i] & 0xff);
    }
 }

int str2mask (char *ipstr) {
   int ip[4];
   int mask;
   int n = sscanf (ipstr, "%d.%d.%d.%d", ip, ip+1, ip+2, ip+3);
   mask = 0xffffffff >> (8*n);

   /* for reasons unknown 0xffffffff >> 32 -> -1, so set to 0  */
   if (mask==-1)  mask=0;

   return mask;
}

/* int str2mask6 (char *ipstr) { */
/*    int ip[16]; */
/*    int mask; */
/*    int n = sscanf (ipstr, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", */
/* 		   ip, ip+1, ip+2, ip+3, ip+4, ip+5, ip+6, ip+7, ip+8, */
/* 		   ip+9, ip+10, ip+11, ip+12, ip+13, ip+14, ip+15); */
/*    mask = 0xffffffffffffffffffffffffffffffff >> (8*n); */

/*    return mask; */
/* } */


void Print_Usage (void) {
printf ("\nmakelocal [-s | {-f l|ll|r|rr} ] <local-net> [ <other-net> [file] ]\n\n");
printf ("Restrict ipaudit data files to conform to given local network (or\n");
printf ("with the -f option either a remote network or a\n");
printf ("combination of local/remote networks).  Ip addresses\n");
printf ("which reside in the local network are considered 'local'.\n");
printf ("Ip addresses outside this network are 'remote'.  If the\n");
printf ("<other-net> is specified, then any address inside this range\n");
printf ("are ignored.  Ip addresses that lie outside of both\n");
printf ("<local-net> and the optional <other-net> are considered\n");
printf ("'remote'.\n");
printf ("\n");
printf ("If no <other-net> is specified or if it is '-', then all\n");
printf ("non-local addresses are other.  If <file> is omitted or set to\n");
printf ("'-' then standard input is read.\n");
printf ("\n");
printf ("If the option 'l' or 'll' or 'r' or 'rr' then only records whose\n");
printf ("first ip is local, or first two ips are local, or first ip is\n");
printf ("other, or first two ips are other will be printed.\n");
printf ("\n");
printf ("With the -s option makelocal prints summary information only.\n");
printf ("The summary consists of the following counts, (1) connections,\n");
printf ("(2) packets, (3) total bytes, (4) incoming bytes,\n");
printf ("(5) outgoing bytes, (6) total of incoming and outgoing,\n");
printf ("(7) internal bytes, (8) external bytes, (9) and other bytes\n\n");
}


/*  Convert int ip to zero padded string such as 001.231.021.124  */
void ip2str (int ip, char buffer[IPLEN4]) {
   int p[4];
   int i;
   for (i=0;i<4;i++) {
      p[i] = ip & 0xff;
      ip >>= 8;
   }
   sprintf (buffer, "%03d.%03d.%03d.%03d", p[3], p[2], p[1], p[0]);
}

/*  Convert int ip to zero padded string such as 001.231.021.124  */
void ip2str6 (char bin_buff[IPLEN6_BIN], char str_buff[IPLEN6]) {
   int p[16];
   int i;
   for (i=0;i<16;i++) {
      p[i] = bin_buff[i] & 0xff;
   }
   sprintf (str_buff, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\0",
	    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8],
	    p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}


/*  Copy ip string into buffer with zero padding  */
void ip2ipf (char *ip, char ipf[IPLEN4]) {
   int slen;
   int olen;
   char *dst, *src;
   /*  return if ip string already padded  */
   slen = strlen(ip);
   if (slen>=IPLEN4-1) {
      strncpy (ipf, ip, IPLEN4);
      return;
   }
   src = ip  + slen  - 1;
   dst = ipf + IPLEN4 - 1;
   *(dst--) = '\0';
   /*  Work forward from end of string  */
   while (dst>=ipf) {
      olen = 3;
      /*  Transfer digits of octet  */
      while (*src!='.' && src>=ip) {
         *(dst--) = *(src--);
         olen--;
      }
      /*  Pad octet with zeroes  */
      while (olen--)
         *(dst--) = '0';
      /*  Add '.'  */
      if (dst>ipf)
         *(dst--) = '.';
      src--;
   }
}


/* ipv6 version of the same */
/* TODO add support for double-colon elided pattern */
void ip2ipf6 (char *ip, char ipf[IPLEN6]) {
   int slen;
   int olen;
   char *dst, *src;
   /*  return if ip string already padded  */
   slen = strlen(ip);
   if (slen>=IPLEN6-1) {
      strncpy (ipf, ip, IPLEN6);
      return;
   }
   src = ip  + slen  - 1;
   dst = ipf + IPLEN6 - 1;
   *(dst--) = '\0';
   /*  Work forward from end of string  */
   while (dst>=ipf) {
      olen = 4;
      /*  Transfer digits of octet  */
      while (*src!=':' && src>=ip) {
         *(dst--) = *(src--);
         olen--;
      }
      /*  Pad octet with zeroes  */
      while (olen--)
         *(dst--) = '0';
      /*  Add ':'  */
      if (dst>ipf)
         *(dst--) = ':';
      src--;
   }
}



int get_range_code (char *ip) {
   if (in_iprange (ip, local_iplist_m,  n_local_iplist_m))
         return 'L';
   else if (n_other_iplist_m && in_iprange (ip, other_iplist_m,  n_other_iplist_m))  {
      return 'O';
   }
   else
      return 'R';
}
   
