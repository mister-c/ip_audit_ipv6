/* ipstrings.c
 *
 * ipstrings - network traffic data gathering
 * By Jon Rifkin <jon.rifkin@uconn.edu>
 * Copyright 1999,2000 Jonathan Rifkin
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
#define DEBUG

#define DUMP
#undef  DUMP

#define HASH
#undef  HASH


/*
------------------------------------------------------------------------
Include Files
------------------------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/
#define VERSION_STR "ipstrings 0.94b2"

#define TRUE 1
#define FALSE 0

#define U_CHAR unsigned char

/*  TCP ports to dump  */
#define NPORT           6

#define P_FTP          21
#define P_TELNET       23
#define P_SUNRPC      111
#define P_LOGIN       513
#define P_INGRESLOCK 1524
#define P_IRC        6667

/*  Misc protocols to dump  */
#define PROT_ICMP       1

/*  Protocols with port info  */
#define PROT_TCP        6
#define PROT_UDP       17


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


/*  Number of 1/10,000 of second in second  */
#define M0SEC 10000

/*  DEFAULT NUMBER OF CHARS IN A STRING  */
#define DEF_MINSTRING 4

/*
------------------------------------------------------------------------
DEBUGGING MACROS
------------------------------------------------------------------------
*/
#ifdef DEBUG
#define WRITEMSG \
	if (debug_m) { \
	printf ("File %s line %d: ", __FILE__, __LINE__); \
	printf ("errmsg <%s>\n", strerror(errno)); fflush(stdout); \
	}
#define WRITEVAR(VAL,FMT) \
	if (debug_m) { \
	printf ("File %s line %d: ", __FILE__, __LINE__); \
	printf ("%s=",#VAL); printf (#FMT, VAL); printf ("\n"); \
	fflush(stdout); \
	}
#else
#define WRITEMSG
#define WRITEVAR(VAL,FMT)
#endif



/*
------------------------------------------------------------------------
MACROS
------------------------------------------------------------------------
*/
/*  Convert time in 1/M0SEC to hours, min, seconds, 1/M0SEC  */
#define HMS(hour,min,sec,sec4) \
   sec   = sec4/M0SEC; \
   sec4 -= M0SEC*sec; \
   min   = sec/60; \
   sec  -= 60*min; \
   hour  = min/60; \
   min  -= 60*hour;


#define ISPRINT(c) \
	((c)>31 && (c)<127)



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
	U_CHAR seq[4];
	U_CHAR ack[4];
	U_CHAR stuff[8];
	U_CHAR data;
	} pkt_struct_t;

typedef struct {
	U_CHAR src[6];
	U_CHAR dst[6];
	U_CHAR ptype[2];     /*  ==0x800 if ip  */
	U_CHAR ip;
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
} ip_struct_t;

typedef struct {
	U_CHAR srcpt[2];
	U_CHAR dstpt[2];
	U_CHAR seq[4];
	U_CHAR ack[4];
	U_CHAR length[1];
	U_CHAR reserved[1];
	U_CHAR window[2];
	U_CHAR checksum[2];
	U_CHAR urgentptr[2];
} tcp_struct_t;

typedef struct {
	U_CHAR srcpt[2];
	U_CHAR dstpt[2];
	U_CHAR length[2];
	U_CHAR checksum[2];
} udp_struct_t;



/*  Start and stop time of each connection  */
typedef struct {
	/*  Time (in sec/10,000) of first and last packet  */
	int first_time, last_time;
	/*  Indentity of machine source for first, last packet  */
	unsigned char first_mach, last_mach;
} datatime_t;


/*  All data for connection  */
typedef struct {
	long       nbyte1, nbyte2;
	int        npkt1, npkt2;
	datatime_t time;
} data_t;







/*
------------------------------------------------------------------------
Global variables
------------------------------------------------------------------------
*/
extern int errno;
extern char *pcap_version[];



/*
------------------------------------------------------------------------
Module variables
------------------------------------------------------------------------
*/
int isig_m=0;

U_CHAR *prots_m = NULL;

U_CHAR *tcp_ports_m = NULL;
U_CHAR *udp_ports_m = NULL;


/*  Flag for writing connection time in output  */
int write_time_m  = FALSE;
int write_eth_m   = FALSE;
int write_ip_m    = FALSE;
int write_port_m  = FALSE;
int write_size_m  = FALSE;

int  debug_m     =  FALSE;

/*  Pcap input file  */
pcap_t *pcapfile_m = NULL;

int npkt_m = 0;      /*  Number of    packets  */
int nippkt_m  = 0;   /*  Number of ip packets  */
int nconn_m   = 0;   /*  Number of connections */

int inport_m = P_FTP;  /*  TCP port to monitor  */
int minstring_m = DEF_MINSTRING;     /*  Minimum number of chars in string  */

/*
------------------------------------------------------------------------
Local Function Prototypes
------------------------------------------------------------------------
*/
void ihandler (int);
void writepkt (struct pcap_pkthdr *, eth_struct_t *, int);
void PrintUsage();

void parse_portstr(char *str);
void add_protocol(int val);
void add_port (int prot, int port);

void *alloc_err (int, int);
char *get_localstr (char *);

int  get_pkttime (struct pcap_pkthdr *);


int cmptime (const void *, const void *);
int cmpip   (const void *, const void *);


/*
------------------------------------------------------------------------
Main Function
------------------------------------------------------------------------
*/
int main (int argc, char *argv[]) {
	char   ebuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr pkthdr;
	eth_struct_t *pkt=NULL;
	eth_struct_t *pkt_orig = NULL;
	struct bpf_program  fcode;
	pcap_dumper_t *df = NULL;
	int dump_this = FALSE;
	int ival;
	int length;
	int i;
	U_CHAR *dumptable = NULL;
	int  optchar;
	int  outputbin  = FALSE;
	int  promisc    = 1;          /*  Default, set promiscuius mode */
	char *progarg   = NULL;
	char *writefile = NULL;
	char *readfile  = NULL;
	int  maxpkt     = 0;
	int  nlen       = PLEN_DEF;   /*  Packet length to dump  */
	char *localstr  = NULL;	      /*  Sorting order for ip address */
	/*  Hash table for ip connections  */
	int  hostonly  = FALSE;
	int  uselimit  = FALSE;
	int  hostportlimit = 0;
	int  hostlimit     = 0;
	U_CHAR nullip[4] = {0,0,0,0};
	int  DataLinkType;
	int  PacketOffset;
	char *filtercmd = "";
	

WRITEMSG
	/*  Read options  */
	while (-1 != (optchar=getopt(argc,argv,"c:def:imn:pr:s:tw:vz"))) {
		switch (optchar) {
			case '?':
				PrintUsage();
				return 1;
			case 'v':
				printf ("%s (compiled %s)\n", VERSION_STR, __DATE__);
				printf ("libpcap version % s\n", pcap_version);
				return 0;
			/*  Debugging option  */
			case 'd':
				debug_m = TRUE;
				break;
			/*  Print ethernet addresses if present  */
			case 'e':
				write_eth_m = TRUE;
				break;
			/*  Get pcap filter string  */
			case 'f':
				filtercmd = strdup (optarg);
				break;
			/*  Write write ip address file  */
			case 'i':
				write_ip_m = TRUE;
				break;
			case 'r':
				readfile = strdup(optarg);
				break;
			case 'w':
				writefile = strdup(optarg);
				break;
			case 'c':
				maxpkt    = atoi(optarg);
				break;
			case 'm':
				promisc   = 0;
				break;
			case 'p':
				write_port_m = TRUE;
				break;
			case 's':
				nlen = atoi(optarg);
				if (nlen<PLEN_MIN)  
					nlen = PLEN_MIN;
				break;
			case 't':
				write_time_m = TRUE;
				break;
			case 'n':
				minstring_m = atoi(optarg);
				break;
			case 'z':
				write_size_m = TRUE;
				break;
			default:
				return 1;
		}
	}
WRITEMSG
	
	
	
	/*  If not reading pcap file need the interface name  */
	if (!readfile && argc-optind<1)  {
		PrintUsage();
		return 0;
	}
	

	/*  Open pcap file  */
	if (readfile) {
		pcapfile_m = pcap_open_offline(readfile, ebuf);
		if (NULL==pcapfile_m) {
			fprintf (stderr, "ERROR:  Cannot open read file %s.\n", readfile);
			exit(1);
		}
	} else {
		pcapfile_m = pcap_open_live(argv[optind], nlen, promisc, 1000, ebuf);
		if (pcapfile_m==NULL) {
			printf("ipstrings: %s (%s)\n", ebuf, "Do you need root?");
			return 1;
		}
	}

	/*  
	Read datalink type  
	This tells us if the datalink is ethernet, ppp, etc.
	*/
	DataLinkType = pcap_datalink(pcapfile_m);

	/*  
	Find packet header offset 
	(to compensate for non-ethernet type packets)
	*/
if (debug_m) {
	switch (DataLinkType) {
		case DLT_EN10MB: 
			printf ("DataLinkType = %s\n", "DLT_EN10MB"); break;
		case DLT_IEEE802: 
			printf ("DataLinkType = %s\n", "DLT_IEEE802"); break;
		case DLT_SLIP: 
			printf ("DataLinkType = %s\n", "DLT_SLIP"); break;
		case DLT_SLIP_BSDOS: 
			printf ("DataLinkType = %s\n", "DLT_SLIP_BSDOS"); break;
		case DLT_PPP: 
			printf ("DataLinkType = %s\n", "DLT_PPP"); break;
		case DLT_PPP_BSDOS: 
			printf ("DataLinkType = %s\n", "DLT_PPP_BSDOS"); break;
		case DLT_FDDI: 
			printf ("DataLinkType = %s\n", "DLT_FDDI"); break;
		case DLT_NULL: 
			printf ("DataLinkType = %s\n", "DLT_NULL"); break;
		case DLT_RAW: 
			printf ("DataLinkType = %s\n", "DLT_RAW"); break;
		case DLT_ATM_RFC1483: 
			printf ("DataLinkType = %s\n", "DLT_ATM_RFC1483"); break;
		default:
			printf ("DataLinkType = %d\n", DataLinkType);
	}
}
	switch (DataLinkType) {
		case DLT_EN10MB:
		case DLT_IEEE802:
			PacketOffset = 0;
			break;
		case DLT_PPP:
			PacketOffset = POFF_PPP - POFF_ETH;
			break;
		case DLT_RAW:
			PacketOffset = POFF_RAW - POFF_ETH;
			break;
		case DLT_NULL:
			PacketOffset = POFF_NULL - POFF_ETH;
			break;
		/*  Currently only know ethernet, ppp, for others we guess  */
		default:
			PacketOffset = 0;
	}

   if (debug_m) 
	   printf ("PacketOffset = %d\n", PacketOffset);

	/*  Compensate for vlan info in packet  */

	/*  
	Insure if ethernet addresses requested that
	captured packets contain them
	*/
	if (write_eth_m && PacketOffset<0) {
		fprintf (stderr, 
			"ERROR:  Cannot print ethernet addresses as requested.\n");
		fprintf (stderr, "Current network interface (%s) ", argv[optind]);
		fprintf (stderr, "is not an ethernet interface.\n");
		exit(2);
	}

	/*  
	Apply user requested packet filter code
	*/
	if (pcap_compile(pcapfile_m, &fcode, filtercmd, 0, 0) < 0)
		printf("compile: %s", pcap_geterr(pcapfile_m));
	if (pcap_setfilter(pcapfile_m, &fcode) < 0)
		printf("setfilter:  %s", pcap_geterr(pcapfile_m));

	/*  Problem with pcap_setfilter?  Sets error, unset here  */
	errno = 0;


	/*  Install interupt handler if reading live */
	if (!readfile) {
		signal (SIGINT,    ihandler);   /*  intercepts  ^C           */
		signal (SIGTERM,   ihandler);   /*  intercepts  ^kill <PID>  */
	}


	/*  Counters  */
	npkt_m    = 0;
	nippkt_m  = 0;

	/*  Open dump file(s)  */
	if (writefile  ) df     = pcap_dump_open(pcapfile_m, writefile);


	/*  Read inteface until interupt signal  */
	while (isig_m==0) {
		npkt_m++;
		pkt_orig = (eth_struct_t *) pcap_next (pcapfile_m, &pkthdr);

		/*  If pkt is null and we're reading file then we're done  */
		/*  Otherwise if reading live try again                    */
		if (pkt_orig==NULL) {
			if (readfile) break;
			else          continue;
		}

		/*  
		Adjust pkt pointer to compenstate for non-ethernet packet 
		Only need pkt_orig for pcap file dump
		*/
		pkt = (eth_struct_t *) ( (U_CHAR *) pkt_orig + PacketOffset );

		/*  Adjust pointer if vlan packet  */
		if ( pkt->ptype[0]==0x81 && pkt->ptype[1]==0 )  
			pkt = (eth_struct_t *) ( (U_CHAR *) pkt + 4 );

		/*  Read next packet unless ip  */
		if ( ! (pkt->ptype[0]==8 && pkt->ptype[1]==0) )   continue;

		/*  Don't exceed limit of ip packets  */
		nippkt_m++;
WRITEVAR(nippkt_m,%d)
		if (maxpkt && nippkt_m>maxpkt)
			break;


		/*  Store packets  */
		writepkt (&pkthdr, pkt, -PacketOffset);


		/*  Using dump  */
		if (writefile) {
				pcap_dump ((U_CHAR *) df, &pkthdr, (U_CHAR *) pkt_orig);
		}

		


	}  /*  Read tcpdump data  */

	if (NULL!=pcapfile_m)  pcap_close(pcapfile_m);

	/*  Clear error if breaking during pcap call  */
	errno = 0;


	/*  Close dump file  */
	if (writefile  ) pcap_dump_close (df);


}



/*
Interupt handler (called when program recieves operating system signal
*/
void ihandler (int cursig) 
	{

	/*  Set signal flag  */
	isig_m = 1;

	/*  Flush buffers  */
	fflush (stdout);

	/*  Close pcap file  */
	pcap_close(pcapfile_m);
	pcapfile_m = NULL;

	/*  RE-INSTALL SIGNAL HANDLER  */
#if 0
	signal (cursig, ihandler);
#endif
	signal (cursig, SIG_DFL);
#ifdef DEBUG
	if (debug_m) {
		struct tm *tm;
		time_t    seconds;
		fprintf (stderr, "ipstrings received signal number <%i>\n", cursig);
		time (&seconds);
		tm = localtime (&seconds);
		fprintf (stderr, "date is <%04d-%02d-%02d-%02d:%02d:%02d>\n", 
		  tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, 
		  tm->tm_hour, tm->tm_min, tm->tm_sec);
		fprintf (stderr, "number of     packets read <%d>\n", npkt_m);
		fprintf (stderr, "number of ip  packets read <%d>\n", nippkt_m);
		}
#endif
	}


/*
Store packet info in hash table, 
keyed by ip1,ip2,port1,por2,protocol
data  is number of incoming/outgoing bytes, packets
*/
void writepkt (struct pcap_pkthdr *pkthdr, eth_struct_t *ep, int PacketOffset) {
	U_CHAR *dptr      = NULL;
	U_CHAR *datastart = NULL;
	U_CHAR *pktend   = NULL;
	U_CHAR *strstart  = NULL;
	U_CHAR *strend    = NULL;
	int  dstpt = 0;
	int  srcpt = 0;
	int  firsttime = 0;
	int  nstring=0;
	int hour, min, sec, msec;
	ip_struct_t  *ip = NULL;
	udp_struct_t *up = NULL;
	tcp_struct_t *tp = NULL;

	/*  Find ip packet start  */
	ip = (ip_struct_t *) &(ep->ip);

	/*  Find end of captured packet  */
	pktend   = (U_CHAR *) ep + pkthdr->caplen + PacketOffset;

	/*  Find ip data start  */
	datastart = (U_CHAR *) ip + 4 * (ip->version[0] & 0x0f);


	/*  Increment start of data by tcp header length  */
	if (ip->prot[0]==PROT_TCP) {
		tp = (tcp_struct_t *) datastart;
		datastart += 4 * (tp->length[0] >> 4);

	/*  Increment start of data by tcp header length  */
	} else if (ip->prot[0]==PROT_UDP) {
		up = (udp_struct_t *) datastart;
		datastart += 8;
	}


	/*  Scan data portion of packet for printable characters  */
	strstart = datastart;
	firsttime = 1;
	while (strstart<pktend) {
		while (!ISPRINT(*strstart) && strstart<pktend) 
			strstart++;
		/*  Find 0 at string end  */
		strend = strstart;
		nstring=0;
		while (*strend!=0 && ISPRINT(*strend) && strend<pktend) {
			strend++;
			nstring++;
		}

		/*  No ending 0, continue searching this packet  */
		if (*strend!=0 && minstring_m==0) {
			strstart = strend+1;
			continue;
		}

		/*  String too short, continue search this packet  */
		if (nstring<minstring_m) {
			strstart = strend+1;
			continue;
		}

		/*  Print address if first time  */
		if (firsttime) {
			firsttime = 0;
			/*  Write ip addresses  */
			if (write_ip_m) {
				printf("%03d.%03d.%03d.%03d %03d.%03d.%03d.%03d ",
					ip->srcip[0], ip->srcip[1], ip->srcip[2], ip->srcip[3], 
					ip->dstip[0], ip->dstip[1], ip->dstip[2], ip->dstip[3]);
			}
			/*  Write protocol number and ports  */
			if (write_port_m) {
				/*  Print udp protocol and port values  */
				if (ip->prot[0]==PROT_UDP) {
					printf (" 17 %6d %6d ", 
						up->srcpt[0]*256 + up->srcpt[1], 
						up->dstpt[0]*256 + up->dstpt[1]);
				/*  Print tcp protocol and port values  */
				} else if (ip->prot[0]==PROT_TCP) {
					printf ("  6 %6d %6d ", 
						tp->srcpt[0]*256 + tp->srcpt[1], 
						tp->dstpt[0]*256 + tp->dstpt[1]);
				/*  Print protocol and dummy port values  */
				} else {
					printf ("%3d %6d %6d ", ip->prot[0], 0, 0);
				}
			}
			/*  Write ethernet addresses  */
			if (write_eth_m) {
				printf ("%02x%02x%02x%02x%02x%02x ",
					ep->src[0], ep->src[1], ep->src[2],
					ep->src[3], ep->src[4], ep->src[5]);
				printf ("%02x%02x%02x%02x%02x%02x ",
					ep->dst[0], ep->dst[1], ep->dst[2],
					ep->dst[3], ep->dst[4], ep->dst[5]);
			}
			/*  Convert seconds from midnight to 24 hour time  */
			if (write_time_m) {
				msec  = get_pkttime(pkthdr);
				HMS(hour,min,sec,msec)
				printf ("%02d:%02d:%02d.%04d ", hour,min,sec,msec);
			}
			/*  Write ip packet size  */
			if (write_size_m) {
				printf ("%d ", ip->length[1] + 256*(int) ip->length[0] + 14);
			}
			/*  Print extra separating space  */
			if (write_ip_m || write_port_m || write_eth_m || write_time_m || write_size_m) 
				printf (" ");
		}

		/*  Print this string, change newlines to '\n' */
		while (*strstart && nstring--) {
			switch (*strstart) {
				case '\n':
					printf ("\\n");
					break;
				case '\r':
					printf ("\\r");
					break;
				default:
					printf ("%c", *strstart);
					break;
			}
			strstart++;
		}
#if 0
		printf ("%s\n", strstart);
#endif

		strstart = strend+1;
	}

	/*  Print linefeed only if packet info printed  */
	if (!firsttime) printf ("\n");

}


void PrintUsage(void) {
	printf ("\nUsage: ipstrings  -defimnprtwvz [interface]\n");
	printf ("  Read tcp packets destined for specific port (default 21, FTP) live\n");
   printf ("   from interface or from dump file and print ascii strings.\n");
	printf ("\n");
	printf ("  -n nchar      -  Minimum length of printed strings, 0 means print only NULL\n");
	printf ("                   terminated strings, default is %d\n",
		DEF_MINSTRING);
	printf ("  -r readfile   -  Read packets from pcap format file, use -r- for standard in\n");
	printf ("                   Don't need interface with this option\n");
   printf ("  -f filterstr  -  Use pcap filters (see tcpdump)\n");
	printf ("  -w writefile  -  Dump selected packets to pcap format file,\n");
	printf ("                   use -w- for standard out\n");
	printf ("  -s nlen       -  Read first <nlen> bytes of each packet live\n");
	printf ("                   (default %d, min %d)\n",
		PLEN_DEF, PLEN_MIN);
	printf ("  -c npacket    -  Only read in specific number of ip packets\n");
	printf ("  -m            -  Do not enter promiscuous mode\n");
	printf ("  -e            -  Print source, destination ethernet address for each packet\n");
	printf ("  -i            -  Print source, destination ip address for each packet\n");
	printf ("  -p            -  Print source, destination port addresses for each packet\n");
	printf ("  -t            -  Print time of day for each packet\n");
	printf ("  -z            -  Print size of each ip packet\n");
	printf ("  -v            -  Print version info\n");
	printf ("  -d            -  Print debug info\n");

	printf ("Examples:\n");
	printf ("  ipstrings -r dump.fil\n");
	printf ("  ipstrings eth0\n");
}



/*
Determine protocols and ports to accept from string of format
	"1:6,21,23,6667:17" means protocols 1 (icmp), 6 (tcp) and 17 (udp)
	For tcp only ports 21,23,6667.
	For udp all ports (default)
*/
void parse_portstr(char *str) {
	char *p;
	char delim;
	int  lastprot = -1;
	int  is_prot;
	int  val;

	is_prot = TRUE;
	delim=' ';
	while (delim) {
		/*  Find : or '\0'  */
		p=str;
		/*  Find next : , '\0'  */
		while (*p!=':' && *p!=',' && *p!='\0') 
		p++;
		delim = *p;
		*p = '\0';
		val = atoi(str);
		str = p+1;

		if (is_prot) {
		lastprot = val;
		add_protocol(val);
		} else {
		add_port (lastprot,val);
		}
		is_prot = (delim==':');
	}
}


void add_protocol(int val) {
	/*  Check for valid protocol  */
	if (val<0 || val>255)
		return;
	/*  ALlocate if not done already  */
	if (NULL==prots_m)
		prots_m = (U_CHAR *) alloc_err(256, sizeof(U_CHAR));
	if (NULL==prots_m) {
		fprintf (stderr, "ERROR: Out of memory\n");
		exit (1);
	}
	/* Accept all ports  */
	prots_m[val] = PROT_ACC_ALL;
	}


void add_port (int prot, int port) {
	/*  Check for valid port  */
	if (prot<0 || prot>0x0ffff)
		return;
	/*  Check for valid protocol  */
	if (prot==PROT_TCP) {
		prots_m[prot] = PROT_ACC_SOME;
		if (NULL==tcp_ports_m) 
		tcp_ports_m = (U_CHAR *) alloc_err(0x010000, sizeof(U_CHAR));
		tcp_ports_m[port] = 1;
	} else if (prot==PROT_UDP) {
		prots_m[prot] = PROT_ACC_SOME;
		if (NULL==udp_ports_m) 
		udp_ports_m = (U_CHAR *) alloc_err(0x010000, sizeof(U_CHAR));
		tcp_ports_m[port] = 1;
	}
}



void *alloc_err (int n, int size) {
	void *p;
	p = calloc (n, size);
	if (NULL==p) {
		fprintf (stderr, "ERROR: Out of memory.\n");
		exit(1);
	}
	return p;
}


/*  
Read and format ip address :
  for example,  "112.51.1" -> "112.051.001"
*/
char *get_localstr(char *instr) {
	/*  Room for string containing formated ip address  */
	char *buffer = (char *) calloc(16,sizeof(char)); 
	char *b = buffer;
	char triplet[3];
	char *p = instr;
	int  i,n;

	/*  Search over all bytes (things between ..)  */
	while (1) {
		n = 0;
		while ((*p>='0' && *p<='9') && n<3) 
			triplet[n++] = *p++;
		/*  Either non-digit or two many digits - return NULL */
		if (*p!='.' && *p!=0) return NULL;
		for (i=n;i<3;i++) *b++ = '0';
		for (i=0;i<n;i++) *b++ = triplet[i];
		*b++ = *p;
		if (*p==0)	return buffer;
		p++;
	}
}


/*
Convert time from pcap pkthdr format (double longs) to 
1/10,000 seconds since midnight
*/
int get_pkttime (struct pcap_pkthdr *pkthdr) {
	struct tm *time;
	time = localtime( (time_t *) &pkthdr->ts.tv_sec);
	return  
		(int)
		pkthdr->ts.tv_usec/100 +  /*  Convert microseconds */
		M0SEC * (time->tm_sec + 60*(time->tm_min + 60*time->tm_hour));
}
