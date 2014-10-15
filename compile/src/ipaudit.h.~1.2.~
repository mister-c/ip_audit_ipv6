#ifndef _IPAUDIT_H
#define _IPAUDIT_H

/*
------------------------------------------------------------------------
Includes
------------------------------------------------------------------------
*/
#include <time.h>


/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/
#define VERSION_STR "ipaudit 0.99"

#define TRUE 1
#define FALSE 0

#define U_CHAR unsigned char


/*  Protocols with port info  */
#define PROT_TCP        6
#define PROT_UDP       17

/* Data dumping period in daemon mode  */
#define DUMP_PERIOD   1800

/*  Flags for udp/tcp accepting all/some ports  */
#define PROT_ACC_ALL    1
#define PROT_ACC_SOME   2

/*  Length of saved packets  */
#define PLEN_DEF 96  /* default  */
#define PLEN_MIN 68  /* min allowed  */

/*  
Length of packet headers  
(culled this info from tcpdump source code)
*/
#define POFF_ETH  14
#define POFF_NULL  4   /* Used by loopback ?  */
#define POFF_PPP   4
#define POFF_RAW   0
#define POFF_LINUX_SLL 16

/*  
Number of hash slots
NOT number of packets, they're unlimited (except for memory)
*/
#define N_HASH_SLOTS 1000000

/*  Number of 1/10,000 of second in second  */
#define M0SEC 10000

#define NO_FILE_WAITING -1

/*  Key positions  */
#define KEY_SRCIP  0
#define KEY_DSTIP  4
#define KEY_SRCPT  8
#define KEY_DSTPT 10
#define KEY_PROT  12
#define KEY_SRCEP 13
#define KEY_DSTEP 19


#define IP_NAME_LEN 256

#define NUM_MYSQL_OPTIONS 5


/*
------------------------------------------------------------------------
DEBUGGING MACROS
------------------------------------------------------------------------
*/
#define WRITEMSG \
   if (debug_g) { \
   printf ("File %s line %d: ", __FILE__, __LINE__); \
   printf ("errmsg <%s>\n", strerror(errno)); fflush(stdout); \
   }
#define WRITETXT(txt) \
   if (debug_g) { \
   printf ("File %s line %d: ** %s **\n", __FILE__, __LINE__, (txt)); \
   }
#define WRITEVAR(VAL,FMT) \
   if (debug_g) { \
   printf ("File %s line %d: ", __FILE__, __LINE__); \
   printf ("%s=",#VAL); printf (#FMT, VAL); printf ("\n"); \
   fflush(stdout); \
   }
#define WRITEHEX(VAL,N) \
   if (debug_g) { \
   int i; \
   printf ("File %s line %d: ", __FILE__, __LINE__); \
   printf ("%s :", #VAL); \
   for (i=0;i<N;i++) { printf (" %02x", VAL[i]); } \
   printf ("\n"); \
   fflush(stdout); \
   }

/*
------------------------------------------------------------------------
Type Definitions
------------------------------------------------------------------------
*/

/*  Packet structure used by pcap library  */
typedef struct {
   U_CHAR src[6];
   U_CHAR dst[6];
   U_CHAR ptype[2];     /*  ==0x800 if ip  */
   U_CHAR version[1];
   U_CHAR service[1];
   U_CHAR length[2];
   U_CHAR id[2];
   U_CHAR flag[2];
   U_CHAR ttl[1];
   U_CHAR prot[1];
   U_CHAR chksum[2];
   U_CHAR srcip[4];
   U_CHAR dstip[4];
   U_CHAR srcpt[2];
   U_CHAR dstpt[2];
   } pkt_struct_t;

typedef struct {
   U_CHAR src[6];
   U_CHAR dst[6];
   U_CHAR ptype[2];     /*  ==0x800 if ip  */
   } eth_struct_t;

typedef struct {
   U_CHAR version[1];
   U_CHAR service[1];
   U_CHAR length[2];
   U_CHAR id[2];
   U_CHAR flag[2];
   U_CHAR ttl[1];
   U_CHAR prot[1];
   U_CHAR chksum[2];
   U_CHAR srcip[4];
   U_CHAR dstip[4];
   U_CHAR srcpt[2];
   U_CHAR dstpt[2];
   } ip_struct_t;



/*  Start and stop time of each connection  */
typedef struct {
   /*  Time (in sec/10,000) of first and last packet  */
   time_t first_time_sec;
   time_t last_time_sec;
   int    first_time_usec; 
   int    last_time_usec;
   /*  Indentity of machine source for first, last packet  */
   unsigned char first_mach, last_mach;
} datatime_t;


/*  All data for connection  */
typedef struct {
   unsigned long  nbyte1, nbyte2;
   unsigned int   npkt1, npkt2;
   U_CHAR     intf;
   datatime_t time;
} data_t;

#endif
