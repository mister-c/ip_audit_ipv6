/*
------------------------------------------------------------------------
Include Files
------------------------------------------------------------------------
*/
#include <stdio.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include "ipaudit.h"
#include "ipdbase.h"
#include "hash.h"
#ifdef USE_MYSQL
#include <mysql.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/
#define FALSE 0
#define TRUE  1
#define SWAP(X,Y,TMP)  {(TMP)=(X); (X)=(Y); (Y)=(TMP);}

/*
------------------------------------------------------------------------
Global variables
------------------------------------------------------------------------
*/
extern int errno;

/*  Flag for writing connection time in output  */
extern int write_date_g;
extern int write_time_g;

/*  IP address range for sorting  */
extern int *iplist_g;
extern int niplist_g;

/*  Flag for printing ethernet addresses  */
extern int printeth_g;
/*  Flag for printing IP addresses in short format  */
extern int printshort_g;
/*  Flag for display of source host info */
extern char probelabel_g[IP_NAME_LEN];
extern int probename_g;

/*  Debug flag  */
extern int  debug_g;

/*
------------------------------------------------------------------------
Function Prototypes
------------------------------------------------------------------------
*/
int cmpip  (const void *ai, const void *bi);

/*  Initialize MySQL  */
#ifdef USE_MYSQL
void mysql_start  (char *, char *, char *, char *, MYSQL *);
#endif


/*
------------------------------------------------------------------------
Local Functions
------------------------------------------------------------------------
*/
/*  Comparison function for sorting by ip packet keys  */
int cmpip  (const void *ai, const void *bi) {

   helem_t *ah = *(helem_t **) ai;
   helem_t *bh = *(helem_t **) bi;
   return memcmp (ah->key, bh->key, 13);
}



/*  Connect to MySQL database */
#ifdef USE_MYSQL
void mysql_start(char *host,char *user,char *passwd,char *db,MYSQL *p_mysql) {

	/*  Initialize mysql connection  */
	mysql_init(p_mysql);
	if (! mysql_real_connect( p_mysql, host, user, passwd, db, 0, NULL, 0)) {
		fprintf(stderr,"ERROR connecting to MySQL: \n%s\n\n",
			mysql_error(p_mysql));
		perror("");
		exit(1);
	}
}
#endif


/*
------------------------------------------------------------------------
Exported Functions
------------------------------------------------------------------------
*/

/*
Retrieve and print packets from hash table in bin format
*/
void bin_writepkt (htable_t *ht, char *outname) {
   helem_t *t;
   data_t  *data;
   FILE    *outfile = stdout;
   int     switch_mach;
   int     first_mach, last_mach;

   /*  Open file if outname is specified and is not '-' or '+'  */
   if (outname && *outname && strcmp("-",outname) && strcmp("+",outname)) { 
      /*  Append file if first char is '+'  */
      if (outname[0]=='+' && outname[1]!=0) 
         outfile = fopen (outname+1, "ab");
      else
         outfile = fopen (outname, "wb");
   }
   if (NULL==outfile) {
      fprintf (stderr, "ERROR:  Cannot open output file <%s>\n", outname);
      exit(1);
   }

   /*  Walk list  */
   ht_initwalk (ht);
   while ((t=ht_getnext(ht))) {

      /*  Get ip addresses and ports  */
      data = (data_t *) t->data;

      /*  Re-order ip addresses if 2nd is local and first is not  */
      switch_mach = 
         !in_iprange (ntohl(*(int*)(t->key)),   iplist_g, niplist_g) &&
          in_iprange (ntohl(*(int*)(t->key+4)), iplist_g, niplist_g);

      if (switch_mach) {
      
         fwrite (t->key+4, 1, 4, outfile);   /* 2nd ip  */
         fwrite (t->key  , 1, 4, outfile);   /* 1st ip  */
         fwrite (t->key+12,1, 1, outfile);   /* protocol */
         fwrite (t->key+10,1, 2, outfile);   /* 2nd port  */
         fwrite (t->key+8, 1, 2, outfile);   /* 1st port  */
         fwrite (&data->nbyte2, 8, 1, outfile);  /* 2nd ip, bytes received  */ 
         fwrite (&data->nbyte1, 8, 1, outfile);  /* 1st ip, bytes received  */
         fwrite (&data->npkt2,  4, 1, outfile);  /* 2nd ip, packets recevied  */
         fwrite (&data->npkt1,  4, 1, outfile);  /* 1st ip, packets received  */

      } else {
      
         fwrite (t->key  , 1, 4, outfile);   /* 1st ip  */
         fwrite (t->key+4, 1, 4, outfile);   /* 2nd ip  */
         fwrite (t->key+12,1, 1, outfile);   /* protocol */
         fwrite (t->key+8, 1, 2, outfile);   /* 1st port  */
         fwrite (t->key+10,1, 2, outfile);   /* 2nd port  */
         fwrite (&data->nbyte1, 8, 1, outfile); /* 1st ip, bytes received  */
         fwrite (&data->nbyte2, 8, 1, outfile); /* 2nd ip, bytes received  */
         fwrite (&data->npkt1,  4, 1, outfile); /* 1st ip, packets received  */
         fwrite (&data->npkt2,  4, 1, outfile); /* 2nd ip, packets recevied  */
      }

      /*  If switching machine order, correct first/last machine id  */
      if (write_time_g) {
         if (switch_mach) {
            first_mach  = 3 - data->time.first_mach;
            last_mach   = 3 - data->time.last_mach;
         } else { 
            first_mach  = data->time.first_mach;
            last_mach   = data->time.last_mach;
         }
         fwrite (&first_mach, sizeof(first_mach), 1, outfile);
         fwrite (&last_mach,  sizeof(last_mach),  1, outfile);
      }
   }

   /*  Close file  */
   if (outname)
      fclose(outfile);
}


/*
Retrieve and print packets from hash table in text format
.. sort by time if writing it
*/
void txt_writepkt (htable_t *ht, char *outname) {
   helem_t  *t;
   data_t   *data;
   FILE     *outfile = stdout;
   char     ip1_v4[16], ip2_v4[16];
   char     ip1_v6[INET6_ADDRSTRLEN], ip2_v6[INET6_ADDRSTRLEN];
   int      pt1, pt2, prot;
   int      msec;
   int      switch_mach;
   int      first_mach, last_mach;
   int      iconn, nconn;
   helem_t  **conn = NULL;
   char     eth1str[13], eth2str[13];
   int      sys_info_err;
   char     hostname[IP_NAME_LEN] = "";
   struct   tm *tfields;

   /*  Open file if outname is specified and is not '-' or '+'  */
   if (outname && *outname && strcmp("-",outname) && strcmp("+",outname)) { 
      /*  Append file if first char is '+'  */
      if (outname[0]=='+' && outname[1]!=0) 
         outfile = fopen (outname+1, "ab");
      else
         outfile = fopen (outname, "wb");
   }
   if (NULL==outfile) {
      fprintf (stderr, "ERROR:  Cannot open output file <%s>\n", outname);
      exit(1);
   }

   /*  Get number of connections  */
   nconn = ht_getcount(ht);
   conn = (helem_t **) calloc (nconn, sizeof(helem_t *));
   if (NULL==conn) {
      fprintf (stderr, 
         "ERROR:  Cannot allocate memory for connection index\n");
      exit(1);
   }

   /*  Make pointer list
   /*  Use history to make pointer list in order of insertion */
   if (write_time_g) {
      t = ht_getoldest(ht);
      nconn = 0;
      while (t) {
         conn[nconn++] = t;
         t = ht_getnewer(ht, t);
      }
//      qsort ( (void *) conn, nconn, sizeof(conn[0]), cmptime);

   /*  No history, walk hash table in order of storage  */
   } else {
      ht_initwalk (ht);
      for (iconn=0;iconn<nconn;iconn++) {
         conn[iconn] = ht_getnext(ht);
      }
      qsort ( (void *) conn, nconn, sizeof(conn[0]), cmpip  );
   }

   
   /* Get system info if required */
	hostname[0]=0;
	if (probelabel_g[0]!=0) {
			strncpy(hostname, probelabel_g,IP_NAME_LEN);
	} else if (probename_g) {
      sys_info_err = gethostname(hostname, 80);
		if (sys_info_err!=0)
			strncpy(hostname,"unknown",IP_NAME_LEN);
   }


   /*  Walk list  */
   for (iconn=0;iconn<nconn;iconn++) {
      t = conn[iconn];


      /* Display probe info if requested */
      if (hostname[0]!=0) {
         fprintf (outfile, "%s ", hostname);
      }


      /* If the packet is ipv4 */
      if( t->key[0] == 0x04){


	/*  Get ip addresses and ports  */
	if (printshort_g) {
	  sprintf (ip1_v4, "%u.%u.%u.%u", 
		   t->key[1], t->key[2], t->key[3], t->key[4]);
	  sprintf (ip2_v4, "%u.%u.%u.%u", 
		   t->key[5], t->key[6], t->key[7], t->key[8]);
	} else {
	  sprintf (ip1_v4, "%03u.%03u.%03u.%03u", 
		   t->key[1], t->key[2], t->key[3], t->key[4]);
	  sprintf (ip2_v4, "%03u.%03u.%03u.%03u", 
		   t->key[5], t->key[6], t->key[7], t->key[8]);
	}
	pt1  = (int) t->key[ 9]*256 + t->key[10];
	pt2  = (int) t->key[11]*256 + t->key[12];
	prot = t->key[13];

	/*  Re-order ip addresses if 2nd is local and first is not  */
	switch_mach = 
	  !in_iprange (ntohl(*(int*)(t->key)),   iplist_g, niplist_g) &&
          in_iprange (ntohl(*(int*)(t->key+4)), iplist_g, niplist_g);

	if (switch_mach) {
      
	  /*  Print key info  */
	  fprintf (outfile, "%s %s %u %u %u", ip2_v4, ip1_v4, prot, pt2, pt1);

	  /*  Data  */
	  data = (data_t *) t->data;
	  fprintf (outfile, " %lu %lu %u %u", 
		   data->nbyte2, data->nbyte1, data->npkt2, data->npkt1);

	} else {
      
	  /*  Print key info  */
	  fprintf (outfile, "%s %s %u %u %u", ip1_v4, ip2_v4, prot, pt1, pt2);

	  /*  Data  */
	  data = (data_t *) t->data;
	  fprintf (outfile, " %lu %lu %u %u", 
		   data->nbyte1, data->nbyte2, data->npkt1, data->npkt2);
	}

	if (printeth_g) {
	  sprintf (eth1str, "%02x%02x%02x%02x%02x%02x", 
		   t->key[14], t->key[15], t->key[16], 
		   t->key[17], t->key[18], t->key[19]);
	  sprintf (eth2str, "%02x%02x%02x%02x%02x%02x", 
		   t->key[20], t->key[21], t->key[22], 
		   t->key[23], t->key[24], t->key[25]);
	}



	/* If the packet is ipv6 */
      } else {


	/*  Get ip addresses and ports  */
	if (printshort_g) {
	  if (inet_ntop(AF_INET6, t->key, ip1_v6, INET6_ADDRSTRLEN) == NULL ||
	      inet_ntop(AF_INET6, t->key+17, ip2_v6, INET6_ADDRSTRLEN) == NULL ){
	    printf("Error writing output\n");
	    exit(1);
	  }
	} else {
	  sprintf (ip1_v6, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", 
		   t->key[1], t->key[2], t->key[3], t->key[4], t->key[5], t->key[6], t->key[7], t->key[8], t->key[9], 
		   t->key[10], t->key[11], t->key[12], t->key[13], t->key[14], t->key[15], t->key[16]);
	  sprintf (ip2_v6, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", 
		   t->key[17], t->key[18], t->key[19], t->key[20], t->key[21], t->key[22], t->key[23], t->key[24], t->key[25], 
		   t->key[26], t->key[27], t->key[28], t->key[29], t->key[30], t->key[31], t->key[32]);
	}
	pt1  = (int) t->key[33]*256 + t->key[34];
	pt2  = (int) t->key[35]*256 + t->key[36];
	prot = t->key[37];

	/*  Re-order ip addresses if 2nd is local and first is not  */
	switch_mach = 
	  !in_iprange (ntohl(*(int*)(t->key+KEY_SRCIP_V6)),   iplist_g, niplist_g) &&
          in_iprange (ntohl(*(int*)(t->key+KEY_DSTIP_V6)), iplist_g, niplist_g);

	if (switch_mach) {
      
	  /*  Print key info  */
	  fprintf (outfile, "%s %s %u %u %u", ip2_v6, ip1_v6, prot, pt2, pt1);

	  /*  Data  */
	  data = (data_t *) t->data;
	  fprintf (outfile, " %lu %lu %u %u", 
		   data->nbyte2, data->nbyte1, data->npkt2, data->npkt1);

	} else {
      
	  /*  Print key info  */
	  fprintf (outfile, "%s %s %u %u %u", ip1_v6, ip2_v6, prot, pt1, pt2);

	  /*  Data  */
	  data = (data_t *) t->data;
	  fprintf (outfile, " %lu %lu %u %u", 
		   data->nbyte1, data->nbyte2, data->npkt1, data->npkt2);
	}

	if (printeth_g) {
	  sprintf (eth1str, "%02x%02x%02x%02x%02x%02x", 
		   t->key[38], t->key[39], t->key[40], 
		   t->key[41], t->key[42], t->key[43]);
	  sprintf (eth2str, "%02x%02x%02x%02x%02x%02x", 
		   t->key[44], t->key[45], t->key[46], 
		   t->key[47], t->key[48], t->key[49]);
	}

	
      }

      if (write_time_g) {

         /*  Convert and print 'first' time field units 
          *  from (sec, usec) -> (date, sec/10,000)  */
         tfields = localtime (&data->time.first_time_sec);
         msec    = data->time.first_time_usec/100;

         fprintf (outfile, " ");
         if (write_date_g) fprintf (outfile, "%04d-%02d-%02d-",
            tfields->tm_year+1900,tfields->tm_mon+1,tfields->tm_mday);
         fprintf (outfile, "%02d:%02d:%02d.%04d", 
            tfields->tm_hour, tfields->tm_min, tfields->tm_sec, msec);

         /*  Convert and print 'last' time field units 
          *  from (sec, usec) -> (date, sec/10,000)  */
         tfields = localtime (&data->time.last_time_sec);
         msec    = data->time.last_time_usec/100;


         fprintf (outfile, " ");
         if (write_date_g) fprintf (outfile, "%04d-%02d-%02d-",
            tfields->tm_year+1900,tfields->tm_mon+1,tfields->tm_mday);
         fprintf (outfile, "%02d:%02d:%02d.%04d", 
            tfields->tm_hour, tfields->tm_min, tfields->tm_sec, msec);

         /* Don't display machine order if dbf output */
         /*  If switching machine order, correct first/last machine id  */
         if (switch_mach) {
            first_mach  = 3 - data->time.first_mach;
            last_mach   = 3 - data->time.last_mach;
         } else { 
            first_mach  = data->time.first_mach;
            last_mach   = data->time.last_mach;
         }

         fprintf (outfile, " %1d %1d", first_mach, last_mach);
      } 

      /*  Print optional ethernet addresses  */
      if (printeth_g) {
         if (switch_mach) {
            fprintf (outfile, " %s %s", eth2str, eth1str);
         } else {
            fprintf (outfile, " %s %s", eth1str, eth2str);
         }
      }

      /*  End line  */
      fprintf (outfile, "\n");

   }

   /*  Close file  */
   if (outname)
      fclose(outfile);
   /*  reclaim storage  */
   if (NULL!=conn) free (conn);
   
}



/*
Retrieve and print packets from hash table in text format
.. sort by time if writing it
*/
void sql_writepkt (htable_t *ht, char *outname) {
   helem_t  *t;
   data_t   *data;
   FILE     *outfile = stdout;
   char     ip1[16], ip2[16];
   int      pt1, pt2, prot;
   int      msec;
   int      switch_mach;
   int      first_mach, last_mach;
   int      iconn, nconn;
   helem_t  **conn = NULL;
   char     eth1str[13], eth2str[13];
   int      sys_info_err;
   char     hostname[IP_NAME_LEN];
   struct   tm *tfields;

   /*  Open file if outname is specified and is not '-' or '+'  */
   if (outname && *outname && strcmp("-",outname) && strcmp("+",outname)) { 
      /*  Append file if first char is '+'  */
      if (outname[0]=='+' && outname[1]!=0) 
         outfile = fopen (outname+1, "ab");
      else
         outfile = fopen (outname, "wb");
   }
   if (NULL==outfile) {
      fprintf (stderr, "ERROR:  Cannot open output file <%s>\n", outname);
      exit(1);
   }

   /*  Get number of connections  */
   nconn = ht_getcount(ht);
   conn = (helem_t **) calloc (nconn, sizeof(helem_t *));
   if (NULL==conn) {
      fprintf (stderr, 
         "ERROR:  Cannot allocate memory for connection index\n");
      exit(1);
   }

   /*  Make pointer list
   /*  Use history to make pointer list in order of insertion */
   if (write_time_g) {
      t = ht_getoldest(ht);
      nconn = 0;
      while (t) {
         conn[nconn++] = t;
         t = ht_getnewer(ht, t);
      }
//      qsort ( (void *) conn, nconn, sizeof(conn[0]), cmptime);

   /*  No history, walk hash table in order of storage  */
   } else {
      ht_initwalk (ht);
      for (iconn=0;iconn<nconn;iconn++) {
         conn[iconn] = ht_getnext(ht);
      }
      qsort ( (void *) conn, nconn, sizeof(conn[0]), cmpip  );
   }

   
   /* Get system info if required */
	hostname[0]=0;
	if (probelabel_g[0]!=0) {
			strncpy(hostname, probelabel_g,IP_NAME_LEN);
	} else if (probename_g) {
      sys_info_err = gethostname(hostname, 80);
		if (sys_info_err!=0)
			strncpy(hostname,"unknown",IP_NAME_LEN);
   }


   /*  Walk list  */
   for (iconn=0;iconn<nconn;iconn++) {
      t = conn[iconn];

      fprintf (outfile, "INSERT INTO ipaudit SET ");

      /* Display probe info if requested */
      if (probename_g) 
            fprintf (outfile, "probename_g='%s',", hostname);

      /*  Get ip addresses and ports  */
      if (printshort_g) {
         sprintf (ip1, "%u.%u.%u.%u", 
            t->key[0], t->key[1], t->key[2], t->key[3]);
         sprintf (ip2, "%u.%u.%u.%u", 
            t->key[4], t->key[5], t->key[6], t->key[7]);
      } else {
         sprintf (ip1, "%03u.%03u.%03u.%03u", 
            t->key[0], t->key[1], t->key[2], t->key[3]);
         sprintf (ip2, "%03u.%03u.%03u.%03u", 
            t->key[4], t->key[5], t->key[6], t->key[7]);
      }
      pt1  = (int) t->key[ 8]*256 + t->key[ 9];
      pt2  = (int) t->key[10]*256 + t->key[11];
      prot = t->key[12];

      /*  Re-order ip addresses if 2nd is local and first is not  */
      switch_mach = 
         !in_iprange (ntohl(*(int*)(t->key)),   iplist_g, niplist_g) &&
          in_iprange (ntohl(*(int*)(t->key+4)), iplist_g, niplist_g);

      if (switch_mach) {
      
         /*  Print key info  */
         fprintf 
            (outfile, "ip2='%s',ip1='%s',protocol=%u,ip2port=%u,ip1port=%u", 
            ip2, ip1, prot, pt2, pt1);

         /*  Data  */
         data = (data_t *) t->data;
         fprintf (outfile, ",ip2bytes=%lu,ip1bytes=%lu,ip2pkts=%u,ip1pkts=%u", 
            data->nbyte2, data->nbyte1, data->npkt2, data->npkt1);

      } else {
      
         fprintf 
            (outfile, "ip1='%s',ip2='%s',protocol=%u,ip1port=%u,ip2port=%u", 
            ip1, ip2, prot, pt1, pt2);

         /*  Data  */
         data = (data_t *) t->data;
            fprintf 
               (outfile, ",ip1bytes=%lu,ip2bytes=%lu,ip1pkts=%u,ip2pkts=%u", 
               data->nbyte1, data->nbyte2, data->npkt1, data->npkt2);
      }

      if (write_time_g) {

         /*  Convert and print 'first' time field units 
          *  from (sec, usec) -> (date, sec/10,000)  */
         tfields = localtime (&data->time.first_time_sec);
         msec    = data->time.first_time_usec/100;

         if (write_date_g) 
         fprintf (outfile ,",constartdate='%04d-%02d-%02d'",
            tfields->tm_year+1900,tfields->tm_mon+1,tfields->tm_mday);
         fprintf (outfile, ",constart='%02d:%02d:%02d',constartmsec=%04d", 
            tfields->tm_hour, tfields->tm_min, tfields->tm_sec, msec);

         /*  Convert and print 'last' time field units 
          *  from (sec, usec) -> (date, sec/10,000)  */
         tfields = localtime (&data->time.last_time_sec);
         msec    = data->time.last_time_usec/100;


         if (write_date_g) 
            fprintf (outfile, ",constopdate='%04d-%02d-%02d'",
            tfields->tm_year+1900,tfields->tm_mon+1,tfields->tm_mday);
         fprintf (outfile, ",constop='%02d:%02d:%02d',constopmsec=%04d",
            tfields->tm_hour, tfields->tm_min, tfields->tm_sec, msec);

      } 

      /*  Print optional ethernet addresses  */
      if (printeth_g) {
         sprintf (eth1str, "%02x%02x%02x%02x%02x%02x", 
            t->key[13], t->key[14], t->key[15], 
            t->key[16], t->key[17], t->key[18]);
         sprintf (eth2str, "%02x%02x%02x%02x%02x%02x", 
            t->key[19], t->key[20], t->key[21], 
            t->key[22], t->key[23], t->key[24]);

         if (switch_mach) {
            fprintf (outfile, ",eth2='%s',eth1='%s'", eth2str, eth1str);
         } else {
            fprintf (outfile, ",eth1='%s',eth2='%s'", eth1str, eth2str);
         }
      }


      /* ; is line terminator for SQL */
      fprintf (outfile, ";\n");

   }

   /*  Close file  */
   if (outname)
      fclose(outfile);
   /*  reclaim storage  */
   if (NULL!=conn) free (conn);
   
}


#ifdef USE_MYSQL
/*
Retrieve and print packets from hash table in text format
.. sort by time if writing it
*/
void mysql_writepkt 
	(htable_t *ht, char mysql_config[NUM_MYSQL_OPTIONS][IP_NAME_LEN]) 
{
	MYSQL mysql;
   char  hostname[IP_NAME_LEN] = "";
   helem_t *t;
   data_t  *data;
	int	sys_info_err;
	char  sqlbuff[1024];
	char  tablename[IP_NAME_LEN] = "connections";
   int   switch_mach;
	int ip1;
	int ip2;
	int prot;
	int pt1;
	int pt2;
	int nbyte1;
	int nbyte2;
	int npkt1;
	int npkt2;
	int sec1;
	int msec1;
	int sec2;
	int msec2;
	int talk1;
	int talk2;
	int swap;
	char **s;
	char * sql_create_template[] = {
		"create table if not exists %s ("
		" probe  varchar(12),"
		" local  int unsigned,"
		" remote int unsigned,"
		" prot   tinyint unsigned,"
		" lport  smallint unsigned,"
		" rport  smallint unsigned,"
		" incb   bigint unsigned,"
		" outb   bigint unsigned,"
		" incp   int unsigned,"
		" outp   int unsigned,"
		" sec1   int unsigned,"
		" msec1  int unsigned,"
		" sec2   int unsigned,"
		" msec2  int unsigned,"
		" talk1  tinyint unsigned,"
		" talk2  tinyint unsigned)",
		"create unique index sec_local on %s (sec1,local)",
		NULL
	};
	
	/*  Initialize mysql connection  */
	mysql_start (
			mysql_config[0], 
			mysql_config[1], 
			mysql_config[2], 
			mysql_config[3],
			&mysql);

	/*  Create database table 'data' if not already present  */
	if (mysql_config[4][0]!=0) {
		strncpy (tablename, mysql_config[4], IP_NAME_LEN);
	}
	s = sql_create_template;
	while (*s) {
		sprintf (sqlbuff, *s, tablename);
		mysql_query (&mysql, sqlbuff);
		*s++;
	}
#if 0
	sprintf (sqlbuff, sql_create_template, tablename, tablename);
	mysql_query (&mysql, sqlbuff);
#endif

   /* Get 'probename'  */
	/*  Use configured probename  */
	if (probelabel_g[0]!=0) {
			strncpy(hostname, probelabel_g,IP_NAME_LEN);

	/*  .. use hostname as probename  */
	} else {
		/*  Read hostname  */
      sys_info_err = gethostname(hostname, 80);
		/*  Truncate name at first '.'  */
		if (sys_info_err==0) {
			char *p = hostname;
			while (*p && *p!='.') p++;
			if (*p=='.') *p=0;
		/*  Cannot get hostname, use 'unknown'  */
		} else {
			strncpy(hostname,"unknown",IP_NAME_LEN);
		}
   }

   /*  Walk hash table in order of storage  */
   ht_initwalk (ht);
	while (t=ht_getnext(ht)) {

      data = (data_t *) t->data;

		ip1    = ntohl(*(unsigned int*)(t->key  ));
		ip2    = ntohl(*(unsigned int*)(t->key+4));
      prot   = t->key[12];
      pt1    = (unsigned int) t->key[ 8]*256 + t->key[ 9];
      pt2    = (unsigned int) t->key[10]*256 + t->key[11];
		nbyte1 = data->nbyte1;
		nbyte2 = data->nbyte2;
		npkt1  = data->npkt1;
		npkt2  = data->npkt2;
		sec1   = (unsigned int) data->time.first_time_sec;
		msec1  = (unsigned int) data->time.first_time_usec;
		sec2   = (unsigned int) data->time.last_time_sec;
		msec2  = (unsigned int) data->time.last_time_usec;
		talk1  = (unsigned int) data->time.first_mach;
		talk2  = (unsigned int) data->time.last_mach;

      /*  Re-order ip addresses if 2nd is local and first is not  */
      switch_mach = 
         !in_iprange (ip1, iplist_g, niplist_g) &&
          in_iprange (ip2, iplist_g, niplist_g);

		/*  Swap local,remote ip order  */
      if (switch_mach) {
			SWAP(ip1,ip2,swap)
			SWAP(pt1,pt2,swap)
			SWAP(nbyte1,nbyte2,swap)
			SWAP(npkt1,npkt2,swap)
			SWAP(sec1,sec2,swap)
			SWAP(msec1,msec2,swap)
			talk1 = 3 - talk1;
			talk2 = 3 - talk2;
		}

		/*  Write data to database using SQL  */
		sprintf (sqlbuff, 
			"insert into %s values ('%s','%u','%u','%u','%u','%u','%u','%u','%u','%u','%u','%u','%u','%u','%u','%u')",
			tablename,
			hostname,
			ip1,
			ip2,
			prot,
			pt1,
			pt2,
			nbyte1,
			nbyte2,
			npkt1,
			npkt2,
			sec1,
			msec1,
			sec2,
			msec2,
			talk1,
			talk2
		);

		mysql_query (&mysql, sqlbuff);

   }
	/*  End of write data  */

	/*  Close connection to mysql  */
	mysql_close(&mysql);	
}
#else
/*  Dummy mysql routine only gives user warning  */
void mysql_writepkt (htable_t *ht, void *mysql_config[]) {
	printf ("ERROR:  Cannot output to MySQL database as requested because\n");
	printf ("MySQL support was not compiled into this instance of ipaudit.\n");
	exit(1);
}
#endif
