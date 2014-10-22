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
#define KEY_VSN_V4    0
#define KEY_SRCIP_V4  1
#define KEY_DSTIP_V4  5
#define KEY_SRCPT_V4  9
#define KEY_DSTPT_V4 11
#define KEY_PROT_V4  13
#define KEY_SRCEP_V4 14
#define KEY_DSTEP_V4 20

/*  Key positions  */
#define KEY_VSN_V6    0
#define KEY_SRCIP_V6  1
#define KEY_DSTIP_V6  17
#define KEY_SRCPT_V6  33
#define KEY_DSTPT_V6  35
#define KEY_PROT_V6   37
#define KEY_SRCEP_V6  38
#define KEY_DSTEP_V6  44



#define IP_NAME_LEN 256

#define NUM_MYSQL_OPTIONS 5


/*
  ------------------------------------------------------------------------
  DEBUGGING MACROS
  ------------------------------------------------------------------------
*/
#define WRITEMSG							\
  if (debug_g) {							\
		printf ("File %s line %d: ", __FILE__, __LINE__);	\
		printf ("errmsg <%s>\n", strerror(errno)); fflush(stdout); \
		}
#define WRITETXT(txt)							\
  if (debug_g) {							\
    printf ("File %s line %d: ** %s **\n", __FILE__, __LINE__, (txt));	\
  }
#define WRITEVAR(VAL,FMT)					\
  if (debug_g) {						\
    printf ("File %s line %d: ", __FILE__, __LINE__);		\
    printf ("%s=",#VAL); printf (#FMT, VAL); printf ("\n");	\
    fflush(stdout);						\
  }
#define WRITEHEX(VAL,N)					\
  if (debug_g) {					\
    int i;						\
    printf ("File %s line %d: ", __FILE__, __LINE__);	\
    printf ("%s :", #VAL);				\
    for (i=0;i<N;i++) { printf (" %02x", VAL[i]); }	\
    printf ("\n");					\
    fflush(stdout);					\
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

/* NOTE
   The ipv4 and ipv6 structs are a little odd. 
   These structs contain the IP header like you
   would expect.

   BUT they also contain a little bit of the TCP header
   (source and destination port). So keep that in mind. */

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
} ipv4_struct_t;

/* My struct for storing ipv6 packets */

typedef struct {
  unsigned char vtf[4];
  unsigned char length[2];
  unsigned char nxthdr[1];
  unsigned char hoplmt[1];
  unsigned char srcip[16];
  unsigned char dstip[16];
  unsigned char srcpt[2];
  unsigned char dstpt[2];
} ipv6_struct_t;



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
