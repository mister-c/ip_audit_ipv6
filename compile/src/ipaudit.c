/* ipaudit.c
 *
 * ipaudit - network traffic data gathering
 * By Jon Rifkin <jon.rifkin@uconn.edu>
 * Copyright 1999-2001 Jonathan Rifkin
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
// #undef  DEBUG

#define DUMP
#undef  DUMP


/*
------------------------------------------------------------------------
Include Files
------------------------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/types.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include "ipaudit.h"
#include "ipdbase.h"
#include "hash.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
------------------------------------------------------------------------
Global variables
------------------------------------------------------------------------
*/
extern int errno;
extern char pcap_version[];

/*  Flag for writing connection time in output  */
int write_date_g = FALSE;
int write_time_g = FALSE;

/*  IP address range for sorting  */
int *iplist_g = NULL;
int niplist_g = 0;

/*  Flag for printing ethernet addresses  */
int printeth_g   = FALSE;
/*  Flag for printing IP addresses in short format  */
int printshort_g = FALSE;
/*  Flag for display of source host info */
char probelabel_g[IP_NAME_LEN] = "";
int probename_g = FALSE;

/*  Debug flag  */
int  debug_g     = FALSE;

/*
------------------------------------------------------------------------
Module variables
------------------------------------------------------------------------
*/
int isig_m=0;

/*  Program options  */
U_CHAR *prots_m = NULL;
U_CHAR *tcp_ports_m = NULL;
U_CHAR *udp_ports_m = NULL;



/*  Pcap input file  */
pcap_t **pcapfile_m = NULL;
char   **pcapfilename_m = NULL;
int    *pcapfiletype_m = NULL;
int    *pcapoffset_m = NULL;
/*  This keeps track of the index of  */
/*  either open pcap files OR live    */
/*  interfaces                        */
int    npcapfile_m  = 0; 

int npkt_m = 0;      /*  Number of    packets  */
int nippkt_m  = 0;   /*  Number of ip packets  */
int nconn_m   = 0;   /*  Number of connections */

int iploc_m   = 0;
int iprem_m   = 0;

/*  Variables for input options  */
unsigned int  vlan_m   = 0;
int  promisc_m         = 1;          /*  Default, set promisc_muius mode */
FILE *pidfile_m        = NULL;
char *progfile_m       = NULL;
char *writefile_m      = NULL;
char *writeallfile_m   = NULL;
char *readfile_m       = NULL;
char *outfile_m        = NULL;
int  maxpkt_m          = 0;
int  hostonly_m        = FALSE;
int  uselimit_m        = FALSE;
int  useicmptype_m     = FALSE;
int  hostportlimit_m   = 0;
int  hostlimit_m       = 0;
int  nlen_m            = PLEN_DEF;   /*  Packet length to dump  */
char *filtercmd_m      = "";
int  nhashslots_m      = N_HASH_SLOTS;
int  allow_duplicate_m = 0;
int  ndump_limit_m     = 0;
int  ndump_all_limit_m = 0;
int fork_m         = FALSE;
int alarm_m        = 0;   /*  Sniff for so many seconds */
int dump_period_m      = DUMP_PERIOD;   /* Period of data dumping, seconds */
char *user_m = NULL;
char *chroot_m = NULL;
/*  If saving only selected packets, 
 *  then also save every packet_sample_m'th packet
 *  to help pick up unanticipated traffic
 */
int packet_sample_m = 0;

U_CHAR ip_m[4]       = "";

/*  Switch for output type  */
char output_type_m[IP_NAME_LEN] = "";
char mysql_config_m[NUM_MYSQL_OPTIONS][IP_NAME_LEN];

/*
------------------------------------------------------------------------
Local Function Prototypes
------------------------------------------------------------------------
*/
void ihandler (int);
void parent_ihandler (int);
int  storepkt 
   (struct pcap_pkthdr *, eth_struct_t *, ipv4_struct_t *, htable_t *, int);
int  storev6pkt 
   (struct pcap_pkthdr *, eth_struct_t *, ipv6_struct_t *, htable_t *, int);
void PrintUsage();

void parse_portstr(char *str);
void add_protocol(int val);
void add_port (int prot, int port);

void *alloc_err (int, int);

int  get_pkttime (struct pcap_pkthdr *);
int  get_packetoffset (int);


int cmptime (const void *, const void *);
int cmpip   (const void *, const void *);

void  str2ip (char *, int *, int *);
char *ip2str (int);
void  parse_ip_range (char *, int **, int *);
int   in_iprange (int ip, int *iplist, int niplist);
void split (char *instr, char ***list, int *nlist);

void read_options     (int argc, char *argv[]);
int  read_config      (char *);
void read_config_line (char *);
void read_interface_str (char *);
void alloc_interface (void);
void open_interface (void);
void set_defaults   (void);
int  impose_host_port_limit (U_CHAR *, int, int);


/*
------------------------------------------------------------------------
Main Function
------------------------------------------------------------------------
*/
int main (int argc, char *argv[]) {
   struct pcap_pkthdr pkthdr;
   U_CHAR       *raw_pkt = NULL;
   U_CHAR       *raw_pkt_save = NULL;
   eth_struct_t *eth_pkt = NULL;
   ipv4_struct_t  *ip4_pkt  = NULL;
   ipv6_struct_t  *ip6_pkt  = NULL;
   pcap_dumper_t *df  = NULL;
   pcap_dumper_t *dfa = NULL;
   int dump_this = FALSE;
   int ival;
   int length;
   int i;
   U_CHAR *dumptable = NULL;
   int  optchar;
   char *progarg   = NULL;
   char config_name[512];
   char *config_name_base = "ipaudit.conf";

   /*  Hash table for ip connections  */
   htable_t *hconn = NULL;
   U_CHAR nullip[4] = {0,0,0,0};
   int  DataLinkType;
   int  PacketOffset;
   int  fd, max_fd;
   int  next_intf;
   int  retval;
   char ebuf[PCAP_ERRBUF_SIZE];
   fd_set rdfs, rdfs_init;
   int  is_not_duplicate;
   int  ndump = 0;
   int  ndump_all = 0;
   int  status;
   int  is_ip4, is_ip6, is_vlan;
   pid_t oldpid, newpid;
   /*  Set so first unselected packet is "sampled" (saved) */
   int  sample_count = 1; 
   char outfile_time  [IP_NAME_LEN] = "";
   char progfile_time [IP_NAME_LEN] = "";
   char writefile_time[IP_NAME_LEN] = "";
   /*  User, Group id  */
	struct passwd *pw_user;
   int uid=0, gid=0;
	int res=0;

   /* Time variables */
   time_t start_t;  /*  Used to name output files  */
   time_t end_t;


   /*  Set default values for options  */
   set_defaults();

   /*  Read default config file from current directory */
   if (read_config(config_name_base)) {
      /*  Read default config from home directory  */
      char *home;
      
      home=getenv("HOME");
      if (home == NULL) home="";
      strncpy (config_name, home, 512-strlen(config_name_base)-2);
      strcat  (config_name, "/");
      strcat  (config_name, config_name_base);
      read_config(config_name);
   }


   /*  Read command line options (override's config file) and interfaces */
   read_options (argc, argv);

   /*  Rationalize options 
    *  (like set,unset  write_time_g, printeth_g if using mysql) 
    *  */
   if (! strcmp ( "MYSQL",  output_type_m) ) {
      write_time_g = TRUE;
      printeth_g   = FALSE;
      probename_g  = TRUE;
   }


   /*  If not reading pcap file need the interface name  */
   /*  Check for interfaces  */
   if (!readfile_m) {
      /*  No interfaces from config file, check command line  */
      if (npcapfile_m==0 && argc-optind>0) read_interface_str(argv[optind]);
      /*  Still no interfaces - print usage and quit  */
      if (npcapfile_m==0) {
         PrintUsage();
         return 0;
      }
   }
   
	/*  If setting user,group then get info *before* possible chroot  */
	if (user_m)  pw_user = getpwnam (user_m);

	/*  Change Root if so configured */
	if (chroot_m) {
		res = chroot (chroot_m);
		/*  Need to be root to chroot()  */
		if (res) {
			printf ("Cannot change root directory; do you need root permission?\n");
			return 1;
		}
	}

   /*  Find starting time  */
   start_t = time(NULL);

   /*  Fork into parent control and child monitoring processes  */
   oldpid = 0;
   while (fork_m) {

      /*  Set previous signal value to 0  */
      isig_m = 0;
      
      /*  Start new child monitoring process  */
      newpid = fork();

      /*  If parent control (stop and start) child monitoring processes  */
      if (newpid) {

         /*  Kill old process  */
         if (oldpid) kill (oldpid, SIGTERM);

         /*  Set signal handling for parent  */
         signal (SIGALRM, parent_ihandler);  /*  intercepts ALARM        */
         signal (SIGINT,  parent_ihandler);  /*  intercepts ^C           */
         signal (SIGTERM, parent_ihandler);  /*  intercepts ^kill <PID>  */

         /*  To prevent drift, set ending time as multiple of dump period  */
         end_t  = start_t + 3*dump_period_m/2;
         end_t -= end_t   %     dump_period_m;
         /*  Set alarm for end of new child  */
         alarm (end_t - start_t);
         start_t = end_t;

         /*  Wait on old child to complete */
         /*  NOTE:  Instead might want to use wait() below  */
         if (oldpid) waitpid (oldpid, &status, 0);

         /*  Wait for alrm signal to stop new child  */
         pause ();

         /*  Send SIGTERM to child so it will clean up  */
         kill (newpid, SIGTERM);

         oldpid = newpid;

         /*  End parent if received SIGTERM OR SIGINT  */
         if (isig_m==SIGTERM || isig_m==SIGINT) {
            if (oldpid) waitpid (oldpid, &status, 0);
            return (0);
         }


      /*  Child process breaks loop and continues below  */
      } else {

         /*  Find starting time, round off to dump period  */
         start_t  = time(NULL);
         start_t += dump_period_m / 2;
         start_t -= start_t  % dump_period_m;

         break;
      }

   }
   /*  End of parent control loop  */

   /*  Evaluate any time strings in output name, 
    *  raw file name and program command  */
   if (outfile_m) 
      strftime (outfile_time, IP_NAME_LEN-1, outfile_m, localtime(&start_t));
   if (progfile_m) 
      strftime (progfile_time, IP_NAME_LEN-1, progfile_m, localtime(&start_t));
   if (writefile_m) 
      strftime (writefile_time, IP_NAME_LEN-1, writefile_m, localtime(&start_t));
   
   /*  Open pcap file  */
   if (readfile_m) {
      npcapfile_m = 1;
      pcapfile_m = malloc (sizeof(pcap_t *));
      pcapfilename_m = (char **) malloc (sizeof(pcapfilename_m[0]));
      pcapfilename_m[0] = readfile_m;
      pcapfile_m[0]     = pcap_open_offline(readfile_m, ebuf);
      pcapoffset_m      = (int *) malloc (sizeof(int));
      pcapoffset_m[0]   = get_packetoffset(pcap_datalink(pcapfile_m[0]));
      if (NULL==pcapfile_m[0]) {
         fprintf (stderr, "ERROR:  Cannot open read file %s.\n", readfile_m);
         exit(1);
      }

   /*  Read live interface(s)  */
   } else if (npcapfile_m) {
      open_interface ();
   }

	/*  Set user,group if so configured  */
	if (user_m) {
		setgid (pw_user->pw_gid);
		setuid (pw_user->pw_uid);
	}

   /*  Allocate room for saved raw packet  */
   raw_pkt_save = (U_CHAR *) malloc (nlen_m);
   

if (debug_g) {
   for (i=0;i<npcapfile_m;i++) {
      printf ("Interface (%s) ", pcapfilename_m[i]);
      DataLinkType = pcap_datalink(pcapfile_m[i]);
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
         case DLT_LINUX_SLL: 
            printf ("DataLinkType = %s\n", "DLT_LINUX_SLL"); break;
         default:
            printf ("DataLinkType = %d\n", DataLinkType);
      }
   }
}



   /*  Install interupt handler if reading live */
   if (!readfile_m) {
      signal (SIGALRM,   ihandler);   /*  intercepts alarm: NOTE, recheck this if doing daemon */
      signal (SIGINT,    ihandler);   /*  intercepts  ^C           */
      signal (SIGTERM,   ihandler);   /*  intercepts  ^kill <PID>  */
   }

   /*  Initialize hash table  */
   hconn = ht_init(N_HASH_SLOTS,HT_HISTORY);


   /*  Counters  */
   npkt_m    = 0;
   nippkt_m  = 0;

   /*  Open dump file using first interface type 
    *  (will only allow interface of this type to write data
    *  because raw packet header depends on interface type).
    */
   if (*writefile_time)  {
      df     = pcap_dump_open(pcapfile_m[0], writefile_time);
      if (NULL==df) {
         fprintf (stderr, "ERROR:  ");
         fprintf (stderr, "Cannot open raw packet file <%s>\n", writefile_time);
         exit(1);
      }
   }

   /*  Open all dump file using first interface type
    */
   if (writeallfile_m)  {
      dfa    = pcap_dump_open(pcapfile_m[0], writeallfile_m);
      if (NULL==dfa) {
         fprintf (stderr, "ERROR:  ");
         fprintf (stderr, "Cannot open raw packet file <%s>\n", writeallfile_m);
         exit(1);
      }
   }


   /*  Initialize info for select()  */
   if (!readfile_m) {
      FD_ZERO (&rdfs_init);
      max_fd = 0;
      for (i=0;i<npcapfile_m;i++) {
         fd = pcap_fileno(pcapfile_m[i]);
         FD_SET (fd, &rdfs_init);
         if (fd>max_fd) max_fd=fd;
      }
      max_fd++;
   }

   /*  If reading live set intf number to cycle throught list, 
    *  if reading file just set interface number to first interface
    *  */
   if (readfile_m) next_intf = 0;
   else            next_intf = npcapfile_m;

   /*  Set alarm to signal us in alarm_m seconds  */
   alarm (alarm_m);

   /*  Read packets until interupt signal  */
   start_t=time(NULL);
   while (isig_m==0) {

      /*  No pending file, run select again  */
      if (!readfile_m) {

         if (next_intf==npcapfile_m) {
            /*  Wait for packet on one of the interfaces  */
            memcpy (&rdfs, &rdfs_init, sizeof(rdfs));
            retval = select (max_fd, &rdfs, NULL, NULL, NULL); 
            next_intf =  0;
            /*  If user interupt caught during select() call, retval will
             *  be <0.  By continuing we re-test isig_m which should now
             *  be set by the interupt handler */
            if (retval<0) continue;
         }

         /*   Search list to find waiting file  */
         while (next_intf<npcapfile_m) {
            if (FD_ISSET(pcap_fileno(pcapfile_m[next_intf]), &rdfs)) break;
            next_intf++;
         }

         /*  No pending files left, jump to top of loop and run select again  */
         if (next_intf>=npcapfile_m) continue;
      }

      /*  Read packet from next available interface/file unless error */

      /*  If network is up (errno==0) read next packet  */
      if (errno==0) {
         raw_pkt = (U_CHAR *) pcap_next (pcapfile_m[next_intf], &pkthdr);
      /*  If network is down, 
       *    - reset error condition 
       *    - indicate that all waiting packets were read, and
       *    - program will wait at select() statement for while net is down
       */
      } else {
         errno=0;
         next_intf=npcapfile_m;
         continue;
      }

      /*  If pkt is null and we're reading file then we're done  */
      /*  Otherwise if reading live try again                    */
      if (raw_pkt==NULL) {
         if (readfile_m) break;
         else          continue;
      }

      /*  Number of packets read (ip or not)  */
      npkt_m++;

      /*  Skip this packet if ethernet and not ip or vlan */
      is_vlan = 0;
      if (pcapoffset_m[next_intf]==POFF_ETH) {
	eth_pkt = (eth_struct_t *) raw_pkt;
      } else if (pcapoffset_m[next_intf]==POFF_LINUX_SLL) {
	eth_pkt = (eth_struct_t *) &raw_pkt[2];
      } else {
	continue;
      }
      is_ip4 = (eth_pkt->ptype[0]==0x08 && eth_pkt->ptype[1]==0x00);
      is_ip6 = (eth_pkt->ptype[0]==0x86 && eth_pkt->ptype[1]==0xDD);
      /*  If not IP, is it VLAN?  */
      if (!is_ip4 && !is_ip6) {
	is_vlan =  eth_pkt->ptype[0]==0x81 && eth_pkt->ptype[1]==0;
	/*  If is VLAN, check for IP further down packet  */
	if (is_vlan) {
	  /* VLAN tags are 12bits... assemble and compare */
	  unsigned int vlan_id = 
	    (eth_pkt->ptype[2] & 0x0F)<<8 |
	    (eth_pkt->ptype[3]);
	  /* If this packet isn't from the VLAN we're listening to, ignore it */
	  if ((vlan_m!=0) && (vlan_id!=vlan_m)) continue;
	  /* Check IP protocol */
	  is_ip4 = (eth_pkt->ptype[4]==0x08 && eth_pkt->ptype[5]==0x00);
	  is_ip6 = (eth_pkt->ptype[4]==0x86 && eth_pkt->ptype[5]==0xDD);
	}
      }
      if (!is_ip4 && !is_ip6) continue;



      /*  Find pointer to ip packet  
	  TODO split this part
	  Either create a pointer to a IPv4 packet or create a pointer to a IPv6 packet
      */
      if(is_ip4){
	ip4_pkt = (ipv4_struct_t *) (raw_pkt + pcapoffset_m[next_intf]);
	if (is_vlan) ip4_pkt = (ipv4_struct_t *) ( ((char *) ip4_pkt) + 4);
      } else {
	ip6_pkt = (ipv6_struct_t *) (raw_pkt + pcapoffset_m[next_intf]);
	if (is_vlan) ip6_pkt = (ipv6_struct_t *) ( ((char *) ip6_pkt) + 4);
      }

      /*  Don't exceed limit of ip packets  */
      nippkt_m++;
      if (maxpkt_m && nippkt_m>maxpkt_m)
         break;


      /*  Dump packet contents  */
#ifdef DEBUG
      if (debug_g) {
         int ibyte, iwidth;
         printf ("IP Packet Count   %d\n", nippkt_m);
         printf ("Raw Packet Length %d\n", pkthdr.len);
         printf ("Captured   Length %d\n", pkthdr.caplen);
         printf ("Captured bytes ...\n");
         iwidth=0;
         for (ibyte=0;ibyte<pkthdr.caplen;ibyte++) {
            printf (" %03d", raw_pkt[ibyte]);
            if (++iwidth==16) {
               printf ("\n");
               iwidth=0;
            }
         }
         printf ("\n");
      }
#endif

      /*  Increase packet size if captured size greater than allocated size
       *  this can only happen when reading packets from a dump file
       */
      if (pkthdr.caplen>nlen_m) {
         if (raw_pkt_save) free (raw_pkt_save);
         nlen_m = pkthdr.caplen;
         raw_pkt_save = (U_CHAR *) malloc (nlen_m);
      }
      

      /*  Save raw packet so can write original packet later to capture
       *  file  */
      memcpy (raw_pkt_save, raw_pkt, pkthdr.caplen);

      /* TODO
	 create alternate statements here that reference the
	 IPv4 and IPv6 structs
	 This section only runs if the user has disabled the option for storing port
	 numbers.

	 Maybe all these memset thingies can be refactored into a seperate method
      */

      /*  Host only storage, set prot, port to zero  */
      /*
      if (hostonly_m) {
         memset (ip_pkt->srcpt, 0, 2);
         memset (ip_pkt->dstpt, 0, 2);
         memset (ip_pkt->prot,  0, 1);
      }
      */
            
      /*  Set ports to 0 if not UDP or TCP  */
      if(is_ip4){
	if ( ip4_pkt->prot[0]!=0x11 && ip4_pkt->prot[0]!=0x06 ) {
	  if (ip4_pkt->prot[0]==1 && useicmptype_m) {
	    memset (ip4_pkt->dstpt, 0, 2);
	  } else {
	    memset (ip4_pkt->srcpt, 0, 2);
	    memset (ip4_pkt->dstpt, 0, 2);
	  }
	}       
      } else{
	if ( ip6_pkt->nxthdr[0]!=0x11 && ip6_pkt->nxthdr[0]!=0x06 ) {
	  if (ip6_pkt->nxthdr[0]==1 && useicmptype_m) {
	    memset (ip6_pkt->dstpt, 0, 2);
	  } else {
	    memset (ip6_pkt->srcpt, 0, 2);
	    memset (ip6_pkt->dstpt, 0, 2);
	  }
	}
      }
      

      /*
#ifdef DEBUG
      if (debug_g) {
      printf ("%03d.%03d.%03d.%03d %03d.%03d.%03d.%03d  %3d %5d %5d\n", 
         ip_pkt->srcip[0],ip_pkt->srcip[1],ip_pkt->srcip[2],ip_pkt->srcip[3],
         ip_pkt->dstip[0],ip_pkt->dstip[1],ip_pkt->dstip[2],ip_pkt->dstip[3],
         ip_pkt->prot[0],
         ip_pkt->srcpt[0]*256+ip_pkt->srcpt[1],
         ip_pkt->dstpt[0]*256+ip_pkt->dstpt[1]);
      }
#endif
      */

      /*  Store packets  */
      if(is_ip4){
	is_not_duplicate = storepkt (&pkthdr, eth_pkt, ip4_pkt, hconn, next_intf);
      } else {
	is_not_duplicate = storev6pkt (&pkthdr, eth_pkt, ip6_pkt, hconn, next_intf);
      }

      /*  Dump all raw packets  */
      if (is_not_duplicate && writeallfile_m) {
         /*  Dump packet  */
         if (ndump_all_limit_m==0 || ndump_all<ndump_all_limit_m) {
            pcap_dump ((U_CHAR *) dfa, &pkthdr, raw_pkt_save);
            ndump_all++;
         }
      }

      /*  Dump raw packets  */
      if (is_not_duplicate && *writefile_time) {

         /*  Check to see if current file has same offset as dump file */
         if (pcapoffset_m[0]!=pcapoffset_m[next_intf]) goto no_dump;

         /*  No protocols/ports specified, so dump all */
         dump_this = FALSE;
         /*  Dump all packets if nothing specified for 
            (1) protocol:ports and 
            (2) packet_sample interval
            (3) specific ipaddress (ip_m)
         */
         if (NULL==prots_m && 0==ip_m[0] && packet_sample_m==0) 
            dump_this = TRUE;


	 if(is_ip4){

	   /*  Is this packet correct protocol/port  */
	   if (prots_m) {
	     dump_this = prots_m[ip4_pkt->prot[0]];

	     /*  If udp or tcp, are ports specified ?  */
	     if (PROT_ACC_SOME==dump_this) {
               dumptable = (PROT_TCP==ip4_pkt->prot[0]) ? 
		 tcp_ports_m : udp_ports_m;
               dump_this = 
		 dumptable[(ip4_pkt->srcpt[0]<<8)+ip4_pkt->srcpt[1]] ||
		 dumptable[(ip4_pkt->dstpt[0]<<8)+ip4_pkt->dstpt[1]];
	     }
	   }

	   /*  Save raw packet if watching this ip address (ip_m) */
	   if ((!dump_this) && ip_m) {
	     dump_this = (!memcmp(ip_m,ip4_pkt->srcip,4) || 
			  !memcmp(ip_m,ip4_pkt->dstip,4));
	   }
         
	   /*  Save raw packet if sampling packets  */
	   if ((!dump_this) && packet_sample_m && --sample_count==0) {
	     dump_this = TRUE;
	     sample_count = packet_sample_m;
	   }

	   /*  Dump packet  */
	   if (dump_this && (ndump_limit_m==0 || ndump<ndump_limit_m)) {
	     pcap_dump ((U_CHAR *) df, &pkthdr, raw_pkt_save);
	     ndump++;
	   }

	 
	 } else {

	   /*  Is this packet correct protocol/port  */
	   if (prots_m) {
	     dump_this = prots_m[ip6_pkt->nxthdr[0]];

	     /*  If udp or tcp, are ports specified ?  */
	     if (PROT_ACC_SOME==dump_this) {
               dumptable = (PROT_TCP==ip6_pkt->nxthdr[0]) ? 
		 tcp_ports_m : udp_ports_m;
               dump_this = 
		 dumptable[(ip6_pkt->srcpt[0]<<8)+ip6_pkt->srcpt[1]] ||
		 dumptable[(ip6_pkt->dstpt[0]<<8)+ip6_pkt->dstpt[1]];
	     }
	   }

	   /*  Save raw packet if watching this ip address (ip_m) */
	   if ((!dump_this) && ip_m) {
	     dump_this = (!memcmp(ip_m,ip6_pkt->srcip,4) || 
			  !memcmp(ip_m,ip6_pkt->dstip,4));
	   }
         
	   /*  Save raw packet if sampling packets  */
	   if ((!dump_this) && packet_sample_m && --sample_count==0) {
	     dump_this = TRUE;
	     sample_count = packet_sample_m;
	   }

	   /*  Dump packet  */
	   if (dump_this && (ndump_limit_m==0 || ndump<ndump_limit_m)) {
	     pcap_dump ((U_CHAR *) df, &pkthdr, raw_pkt_save);
	     ndump++;
	   }

	 
	 }

      }

      no_dump:


      /*  Select next file in list for checking  */
      if (!readfile_m) next_intf++;

   }  /*  Read tcpdump data  */


   /*  Close files  */
   for (i=0;i<npcapfile_m;i++) 
      if (NULL!=pcapfile_m[i])  pcap_close(pcapfile_m[i]);

   /*  Clear error if breaking during pcap call  */
   errno = 0;


   /*  Close dump file(s)  */
   if (*writefile_time ) pcap_dump_close (df );
   if (writeallfile_m  ) pcap_dump_close (dfa);

   /*  Write packet info  */
   if        (! strcmp ( "BINARY", output_type_m) ) {
      bin_writepkt(hconn, outfile_time);

   } else if (! strcmp ( "SQL",    output_type_m) ) {
      sql_writepkt(hconn, outfile_time);

   } else if (! strcmp ( "MYSQL",  output_type_m) ) {
      mysql_writepkt(hconn, mysql_config_m);

   } else {
      txt_writepkt(hconn, outfile_time);
   }

   /*  Free hash table  */
#if 0
   /*  Experience shows that it takes a long time to explicitly free these, 
    *  so let the OS handle it */
   ht_free(hconn);
#endif

   /*  Call next program  */
   if (*progfile_time) {
      progarg = strchr (progfile_time, ' ');
      if (progarg) {
      *progarg++ = '\0';
      }
      execl (progfile_time, progfile_time, progarg, NULL);
   }
}



/*
Interupt handler (called when program recieves SIGTERM, SIGINT)
*/
void ihandler (int cursig) {
   int i;

   /*  Set flag to terminate main() polling loop 
    *  when excution reaches bottom  */
   isig_m = 1;

   /*  Change interface read() to non-blocking so that program does not
    *  have to wait for read() to encounter network data before function
    *  call returns
    */
#if 0
   i = pcap_fileno(pcapfile_m);
   fcntl (i, F_SETFL, fcntl(i,F_GETFL) | O_NONBLOCK);
#endif

   /*  FLUSH BUFFERS  */
   fflush (stdout);

   /*  RE-INSTALL SIGNAL HANDLER IF SIGINT (CTRL-C) */
   /*  NOTE:  2003-02-16  Re-installing signal handler for SIGTERM caused
    *  problem with two different dual-cpu machines (but not two different
    *  single-cpu machines) - apparently when parent called 'kill (newpid, SIGTERM);'
    *  once, the child sometimes (about 50%) received signals *twice*.  Thus
    *  re-installing default signal handler for child would result in child
    *  being terminated by second signal.  The obvious cure was to not re-install
    *  SIGTERM signal handler */
   if (cursig==SIGINT) signal (cursig, SIG_DFL);
#ifdef DEBUG
   if (debug_g) {
      struct tm *tm;
      time_t    seconds;
      fprintf (stderr, "ipaudit received signal number <%i>\n", cursig);
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
Interupt handler (called when parent receives ALRM or SIGINT, SIGTERM)
*/
void parent_ihandler (int cursig) {
   int i;

   /*  Set flag to terminate main() polling loop 
    *  when excution reaches bottom  */
   isig_m = cursig;


   /*  RE-INSTALL SIGNAL HANDLER  */
   signal (cursig, SIG_DFL);

   }


/*
Store packet info in hash table, 
keyed by ip1,ip2,port1,por2,protocol
data  is number of incoming/outgoing bytes, packets
*/
int storepkt (
struct pcap_pkthdr *pkthdr, 
eth_struct_t *ep, 
ipv4_struct_t *ip,
htable_t *ht,
int intf
) {
   U_CHAR     key[26];  /*  space for ip1,ip2,prot,prt1,prt2,eth1,eth2  */
   data_t     *data;
   int        ndata;
   int        length;
   data_t     idata;
   datatime_t idatatime;
   int        datasize;
   int        keysize;
   int        is_unique_packet;
   int        is_new_key;

   /*  Calculate data packet length  */
   length = ip->length[1] + 256*(int) ip->length[0] + 14;

   key[KEY_VSN_V4] = 0x04; /* version number */

   /*  Make key - order so smallest ip first store data,
    *  and reorder data accordingly  */
   if (memcmp(ip->srcip, ip->dstip, 4) < 0) {
      memcpy (key + KEY_SRCIP_V4, ip->srcip, sizeof(ip->srcip));
      memcpy (key + KEY_DSTIP_V4, ip->dstip, sizeof(ip->dstip));
      memcpy (key + KEY_SRCPT_V4, ip->srcpt, sizeof(ip->srcpt));
      memcpy (key + KEY_DSTPT_V4, ip->dstpt, sizeof(ip->dstpt));
      if (ep) {
         memcpy (key + KEY_SRCEP_V4, ep->src,   sizeof(ep->src));
         memcpy (key + KEY_DSTEP_V4, ep->dst,   sizeof(ep->dst));
      }
      /*  Order data according to ip order  */
      idata.nbyte1 = 0;
      idata.nbyte2 = length;
      idata.npkt1  = 0;
      idata.npkt2  = 1;
      idata.intf   = intf;

   } else {
      memcpy (key + KEY_SRCIP_V4, ip->dstip, sizeof(ip->dstip));
      memcpy (key + KEY_DSTIP_V4, ip->srcip, sizeof(ip->srcip));
      memcpy (key + KEY_SRCPT_V4, ip->dstpt, sizeof(ip->dstpt));
      memcpy (key + KEY_DSTPT_V4, ip->srcpt, sizeof(ip->srcpt));
      if (ep) {
         memcpy (key + KEY_SRCEP_V4, ep->dst,   sizeof(ep->dst));
         memcpy (key + KEY_DSTEP_V4, ep->src,   sizeof(ep->src));
      }
      /*  Order data according to ip order  */
      idata.nbyte1 = length;
      idata.nbyte2 = 0;
      idata.npkt1  = 1;
      idata.npkt2  = 0;
      idata.intf   = intf;
   }
   /*  Save protocol  */
   memcpy (key + KEY_PROT_V4, ip->prot,  sizeof(ip->prot));

   /*  Set keysize according to whether we are storing eth packets  */
   if (printeth_g) {
      keysize = sizeof(key);
   } else {
      keysize = sizeof(key)-12;
   }

   /*  Store time if requested  */
   if (write_time_g) {
      idata.time.first_time_sec  = pkthdr->ts.tv_sec;
      idata.time.first_time_usec = pkthdr->ts.tv_usec;
      /*  If machine 1 received packet, then source was 2, else 1  */
      idata.time.first_mach = (idata.npkt1==1) ? 2 : 1;
      /*  Set first and last machine info the same  */
      idata.time.last_time_sec  = idata.time.first_time_sec;
      idata.time.last_time_usec = idata.time.first_time_usec;
      idata.time.last_mach      = idata.time.first_mach;
      /*  Set size of full data structure  */
      datasize = sizeof(data_t);

   /*  Set datasize to not store time (saves memory space)  */
   } else {
      datasize = sizeof(data_t) - sizeof(datatime_t);
   }

#ifdef DUMP
printf ("%03u.%03u.%03u.%03u ", key[1], key[2], key[3], key[4]);
printf ("%03u.%03u.%03u.%03u ", key[5], key[6], key[7], key[8]);
printf ("%u %u %u %d %d\n", key[13], (int )key[9]*256+key[10], (int )key[11]*256+key[12], length, 1);
#endif

   /*  Assume for now that this packet is unique  */
   is_unique_packet = 1;

   /*  See if key is present in hash table  */
   is_new_key = 
      ! ht_findkey(ht,(U_CHAR *)&key, keysize, (U_CHAR **)&data,&ndata);

   /*  
    *  Call function that (1) tests for key overflow and if so,
    *  (2) maps key to smaller set.  Then call key search again.
    *  */
   if (impose_host_port_limit (key, keysize, TRUE)) {
      is_new_key = 
         ! ht_findkey(ht,(U_CHAR *)&key, keysize, (U_CHAR **)&data,&ndata);
   }

   /*  A new key must be stored  */
   if ( is_new_key ) {

      /*  Store time if requested  */
      if (write_time_g) {
         idata.time.first_time_sec  = pkthdr->ts.tv_sec;
         idata.time.first_time_usec = pkthdr->ts.tv_usec;
         /*  If machine 1 received packet, then source was 2, else 1  */
         idata.time.first_mach = (idata.npkt1==1) ? 2 : 1;
         /*  Set first and last machine info the same  */
         idata.time.last_time_sec  = idata.time.first_time_sec;
         idata.time.last_time_usec = idata.time.first_time_usec;
         idata.time.last_mach      = idata.time.first_mach;
         /*  Set size of full data structure  */
         datasize = sizeof(data_t);
   
      /*  Set datasize to not store time (saves memory space)  */
      } else {
         datasize = sizeof(data_t) - sizeof(datatime_t);
      }

      ht_storekey (ht, (U_CHAR *) &key, keysize, (U_CHAR *) &idata, datasize);
      nconn_m++;  /*  Increment number of connections  */

   /*  Key already present, update info  
    *  If this key (ip address/protocol/port) already seen on a
    *  different interface, we ignore this instance since it
    *  must(?) be duplicate information  */
   } else if (allow_duplicate_m || data->intf==intf) {
      data->nbyte1 += idata.nbyte1;
      data->nbyte2 += idata.nbyte2;
      data->npkt1  += idata.npkt1;
      data->npkt2  += idata.npkt2;
      /*  Update last packet time  */
      if (write_time_g) {
         data->time.last_time_sec   = idata.time.last_time_sec;
         data->time.last_time_usec  = idata.time.last_time_usec;
         data->time.last_mach       = idata.time.last_mach;
      }
#ifdef DUMP
printf ("data idata  <%u %u %u %u>a  <%u %u %u %u>\n", 
data[0], data[1], data[2], data[3],
idata[0], idata[1], idata[2], idata[3]);
#endif

   /*  This packet must also be present on another interface  */
   } else {
      is_unique_packet = 0;
   }
   return is_unique_packet;
}



/*
Store packet info in hash table, 
keyed by ip1,ip2,port1,por2,protocol
data  is number of incoming/outgoing bytes, packets
*/
int storev6pkt (
struct pcap_pkthdr *pkthdr, 
eth_struct_t *ep, 
ipv6_struct_t *ip, 
htable_t *ht,
int intf
) {
   U_CHAR     key[50];  /*  space for ip1,ip2,prot,prt1,prt2,eth1,eth2  */
   data_t     *data;
   int        ndata;
   int        length;
   data_t     idata;
   datatime_t idatatime;
   int        datasize;
   int        keysize;
   int        is_unique_packet;
   int        is_new_key;

   /*  Calculate data packet length  */
   length = ip->length[1] + 256*(int) ip->length[0] + 14;

   key[KEY_VSN_V6] = 0x06; /* version number */

   /*  Make key - order so smallest ip first store data,
    *  and reorder data accordingly  */
   if (memcmp(ip->srcip, ip->dstip, 4) < 0) {
      memcpy (key + KEY_SRCIP_V6, ip->srcip, sizeof(ip->srcip));
      memcpy (key + KEY_DSTIP_V6, ip->dstip, sizeof(ip->dstip));
      memcpy (key + KEY_SRCPT_V6, ip->srcpt, sizeof(ip->srcpt));
      memcpy (key + KEY_DSTPT_V6, ip->dstpt, sizeof(ip->dstpt));
      if (ep) {
         memcpy (key + KEY_SRCEP_V6, ep->src,   sizeof(ep->src));
         memcpy (key + KEY_DSTEP_V6, ep->dst,   sizeof(ep->dst));
      }
      /*  Order data according to ip order  */
      idata.nbyte1 = 0;
      idata.nbyte2 = length;
      idata.npkt1  = 0;
      idata.npkt2  = 1;
      idata.intf   = intf;

   } else {
      memcpy (key + KEY_SRCIP_V6, ip->dstip, sizeof(ip->dstip));
      memcpy (key + KEY_DSTIP_V6, ip->srcip, sizeof(ip->srcip));
      memcpy (key + KEY_SRCPT_V6, ip->dstpt, sizeof(ip->dstpt));
      memcpy (key + KEY_DSTPT_V6, ip->srcpt, sizeof(ip->srcpt));
      if (ep) {
         memcpy (key + KEY_SRCEP_V6, ep->dst,   sizeof(ep->dst));
         memcpy (key + KEY_DSTEP_V6, ep->src,   sizeof(ep->src));
      }
      /*  Order data according to ip order  */
      idata.nbyte1 = length;
      idata.nbyte2 = 0;
      idata.npkt1  = 1;
      idata.npkt2  = 0;
      idata.intf   = intf;
   }
   /*  Save protocol  */
   memcpy (key + KEY_PROT_V6, ip->nxthdr,  sizeof(ip->nxthdr));

   /*  Set keysize according to whether we are storing eth packets  */
   if (printeth_g) {
      keysize = sizeof(key);
   } else {
      keysize = sizeof(key)-12;
   }

   /*  Store time if requested  */
   if (write_time_g) {
      idata.time.first_time_sec  = pkthdr->ts.tv_sec;
      idata.time.first_time_usec = pkthdr->ts.tv_usec;
      /*  If machine 1 received packet, then source was 2, else 1  */
      idata.time.first_mach = (idata.npkt1==1) ? 2 : 1;
      /*  Set first and last machine info the same  */
      idata.time.last_time_sec  = idata.time.first_time_sec;
      idata.time.last_time_usec = idata.time.first_time_usec;
      idata.time.last_mach      = idata.time.first_mach;
      /*  Set size of full data structure  */
      datasize = sizeof(data_t);

   /*  Set datasize to not store time (saves memory space)  */
   } else {
      datasize = sizeof(data_t) - sizeof(datatime_t);
   }

#ifdef DUMP

//This prints the src and dest ips
printf ("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x ", key[1], key[2], key[3], key[4], key[5], key[6],
	   key[7], key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15], key[16]);
printf ("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x ", key[17], key[18], key[19], key[20], key[21], key[22],
	   key[23], key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31], key[32]);
//This prints the protocol followed by the two port numbers then the length and the number 1 for some reason
printf ("%u %u %u %d %d\n", key[37], (int )key[33]*256+key[34], (int )key[35]*256+key[36], length, 1);

#endif

   /*  Assume for now that this packet is unique  */
   is_unique_packet = 1;

   /*  See if key is present in hash table  */
   is_new_key = 
      ! ht_findkey(ht,(U_CHAR *)&key, keysize, (U_CHAR **)&data,&ndata);

   /*  
    *  Call function that (1) tests for key overflow and if so,
    *  (2) maps key to smaller set.  Then call key search again.
    *  */
   if (impose_host_port_limit (key, keysize, FALSE)) {
      is_new_key = 
         ! ht_findkey(ht,(U_CHAR *)&key, keysize, (U_CHAR **)&data,&ndata);
   }

   /*  A new key must be stored  */
   if ( is_new_key ) {

      /*  Store time if requested  */
      if (write_time_g) {
         idata.time.first_time_sec  = pkthdr->ts.tv_sec;
         idata.time.first_time_usec = pkthdr->ts.tv_usec;
         /*  If machine 1 received packet, then source was 2, else 1  */
         idata.time.first_mach = (idata.npkt1==1) ? 2 : 1;
         /*  Set first and last machine info the same  */
         idata.time.last_time_sec  = idata.time.first_time_sec;
         idata.time.last_time_usec = idata.time.first_time_usec;
         idata.time.last_mach      = idata.time.first_mach;
         /*  Set size of full data structure  */
         datasize = sizeof(data_t);
   
      /*  Set datasize to not store time (saves memory space)  */
      } else {
         datasize = sizeof(data_t) - sizeof(datatime_t);
      }

      ht_storekey (ht, (U_CHAR *) &key, keysize, (U_CHAR *) &idata, datasize);
      nconn_m++;  /*  Increment number of connections  */

   /*  Key already present, update info  
    *  If this key (ip address/protocol/port) already seen on a
    *  different interface, we ignore this instance since it
    *  must(?) be duplicate information  */
   } else if (allow_duplicate_m || data->intf==intf) {
      data->nbyte1 += idata.nbyte1;
      data->nbyte2 += idata.nbyte2;
      data->npkt1  += idata.npkt1;
      data->npkt2  += idata.npkt2;
      /*  Update last packet time  */
      if (write_time_g) {
         data->time.last_time_sec   = idata.time.last_time_sec;
         data->time.last_time_usec  = idata.time.last_time_usec;
         data->time.last_mach       = idata.time.last_mach;
      }
#ifdef DUMP
printf ("data idata  <%u %u %u %u>a  <%u %u %u %u>\n", 
data[0], data[1], data[2], data[3],
idata[0], idata[1], idata[2], idata[3]);
#endif

   /*  This packet must also be present on another interface  */
   } else {
      is_unique_packet = 0;
   }
   return is_unique_packet;
}





void PrintUsage(void) {
   printf ("\nUsage: ipaudit [OPTIONS] [interface[:interface[:interface..]]]\n");
   printf ("  Read and record info on ip connections and optionally\n");
   printf ("  dump packets to file\n");
   printf ("\n");
   printf ("  -b            -  Write output in binary format (experimental)\n");
   printf ("  -c npacket    -  Only read in specific number of ip packets\n");
   printf ("  -d            -  Turn on debugging output\n");
   printf ("  -e            -  Write out ethernet addresses\n");
   printf ("  -f filterstr  -  Use pcap filters (see tcpdump)\n");
   printf ("  -g config     -  Read config file (instead of default)\n");
   printf ("  -i pidfile    -  Write process id to file\n");
   printf ("  -l ip-range   -  Order output ip address pairs by ip range\n");
   printf ("  -m            -  Do not turn on promiscuous mode\n");
   printf ("  -o outfile    -  Place output in 'outfile'. Default is stdout\n");
   printf ("  -p string     -  Dump only selected ip protocols and ports\n");
   printf ("     string format -p n:n:n,p,p:n where n is protocol number\n");
   printf ("     and p is port number (only for protocols 6 (tcp) and 17 (udp)\n");
   printf ("  -q            -  Output in SQL format for direct database input\n");
   printf ("  -r readfile   -  Read packets from pcap format file\n");
   printf ("                   Don't need interface with this option\n");
   printf ("  -s nlen       -  Dump first <nlen> bytes of each packet (default %d, min %d)\n",
      PLEN_DEF, PLEN_MIN);
   printf ("  -t             - Write out connection start and stop times\n");
   printf ("  -v            -  Print version and exit.\n");
   printf ("  -w writefile  -  Dump selected packets to pcap format file \"writefile\"\n");
   printf ("  -x program    -  Run program when done\n");
   printf ("  -z conf-opt   -  Read config file option from command line\n");
   printf ("  -A all[,lim]  -  Dump all packetes to pcap format file \"all\".\n");
   printf ("                   Limit number of packets to \"lim\" (optional).\n");
   printf ("  -C            -  Preserve ICMP type/code in source port field\n");
   printf ("  -D period     -  Daemon mode.\n");
   printf ("  -E nsec       -  Stop after nsec seconds.\n");
   printf ("  -G            -  Do not read config file\n");
   printf ("  -H            -  Store hosts only (protocol, ports set to zero)\n");
   printf ("  -I ipaddr     -  Dump all packets with 'ipaddr'\n");
   printf ("  -L hostportlimit,hostlimit\n");
   printf ("                -  Max number of hostport,host packets recorded\n");   
   printf ("  -M            -  Allow double logging of packets which pass between\n");
   printf ("                   multiple interfaces\n");
   printf ("  -N nhashslot  -  Number of hash slots\n");
   printf ("  -O loc,rem    -  Local/remote host overflow ip\n");
   printf ("  -P            -  Display name of host running ipaudit as part of output\n");
   printf ("  -R n          -  If using -w, save every n'th unselected packet\n");
   printf ("  -S            -  Print ip addresses in short format (no leading 0s)\n");
   printf ("  -T             - Write out connection start and stop dates and times\n");
   printf ("  -V vlanid     -  Limit to packets belonging to a specific VLAN (802.1q tagging)\n");
   printf ("  -W dumplimit  -  Limit to number of packets written with -w command\n");
   printf ("Example:\n");
   printf ("  ipaudit -w dump.fil -p1:2:6,21,23  eth0\n");
   printf ("Write only packets with protocols 1 (icmp), 2 (?), and 6 (tcp)\n");
   printf ("and tcp ports 21 and 23 (ftp,telnet)\n\n");
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



/*  Comparison function for sorting by time  */
int cmptime (const void *ai, const void *bi) {
   helem_t *ah = *(helem_t **) ai;
   helem_t *bh = *(helem_t **) bi;
   data_t  *ad = (data_t *) (ah->data);
   data_t  *bd = (data_t *) (bh->data);
   if (ad->time.first_time_sec  < bd->time.first_time_sec ) return -1;
   if (ad->time.first_time_sec  > bd->time.first_time_sec ) return  1;
   if (ad->time.first_time_usec < bd->time.first_time_usec) return -1;
   if (ad->time.first_time_usec > bd->time.first_time_usec) return  1;
   if (ad->time.last_time_sec   < bd->time.last_time_sec  ) return -1;
   if (ad->time.last_time_sec   > bd->time.last_time_sec  ) return  1;
   if (ad->time.last_time_usec  < bd->time.last_time_usec ) return -1;
   if (ad->time.last_time_usec  > bd->time.last_time_usec ) return  1;
   return 0;
}


#if 0
/*  Transfered to header  */
/*  Comparison function for sorting by ip packet keys  */
int cmpip  (const void *ai, const void *bi) {

   helem_t *ah = *(helem_t **) ai;
   helem_t *bh = *(helem_t **) bi;
   return memcmp (ah->key, bh->key, 13);
}
#endif


int get_packetoffset (int DataLinkType) {
   int PacketOffset;
   switch (DataLinkType) {
      case DLT_EN10MB:
      case DLT_IEEE802:
         PacketOffset = POFF_ETH;
         break;
      case DLT_PPP:
         PacketOffset = POFF_PPP;
         break;
      case DLT_RAW:
         PacketOffset = POFF_RAW;
         break;
      case DLT_NULL:
         PacketOffset = POFF_NULL;
         break;
      case DLT_LINUX_SLL:
         PacketOffset = POFF_LINUX_SLL;
         break;
      /*  Currently only know ethernet, ppp, for others we guess  */
      default:
         PacketOffset = 0;
   }
   return PacketOffset;
}



void parse_ip_range (char *arg_in, int **iplist, int *niplist) {
   char *arg_cpy = (char *) malloc (strlen(arg_in)+1);
   char *ipstr   = (char *) malloc (strlen(arg_in)+1);
   char *netstr  = (char *) malloc (strlen(arg_in)+1);
   char *range1  = NULL;
   char *range2  = NULL;
   int  nrange;
   int  mask;
   int  net;
   int  ip1, ip2;
   int  n;
   char *p;

   /*  Free iplist if previously allocated 
    *  (should be initialized to NULL at program load)
    */
   if (*iplist) free(*iplist);
   *iplist = NULL;

   /*  Count number of ranges (equals number of : + 1 )  */
   p = arg_in;
   n = 1;
   while (*p++) {
      if (*p==':') n++;
   }

   /*  allocate storage  */
   *iplist = (int *) malloc (2 * n * sizeof(int));
   if (*iplist==NULL) {
      *niplist = 0;
      return;
   }

   strcpy  (arg_cpy, arg_in);
   range2 = arg_cpy;

   /*  break string into separate ranges  */
   *niplist = 0;
   while (NULL!=range2) {

      /*  Break arg into (1st range):(remaining ranges)  */
      range1 = range2;
      range2 = strchr(range1, ':');
      if (NULL!=range2) *range2++ = '\0';


      /*  Look for range expressed as (lo ip)-(hi ip)  */
       if (2==sscanf (range1, "%[0-9.]-%[0-9.]", ipstr, netstr)) {
         str2ip(ipstr,  &ip1, &mask);
         str2ip(netstr, &ip2, &mask);

      /*  break range into (ip)/(net)  */
      } else if (2==sscanf (range1, "%[0-9.]/%[0-9]", ipstr, netstr)) {

         /*  read ip address  */
         str2ip (ipstr, &ip1, &mask);

         net = atoi(netstr);
         if (net<0) net=0;
         else if (net>32) net=32;
         mask = 0xffffffff >> net;
         if (mask==-1) mask = 0;
         ip2 = ip1 | mask;

      /*  Look for single ip address  */
      } else if (sscanf (range1, "%[0-9.].%[0-9].", ipstr, netstr)) {
         str2ip (ipstr, &ip1, &mask);
         ip2 = ip1 | mask;

      /*  Bad input format  */
      } else {
         fprintf (stderr, "ERROR:  Cannot read network range argument (-l option).\n");
         fprintf (stderr, "  Program continues with using default network range.\n");
         *niplist = 0;
         if (NULL!=*iplist) free (*iplist);
         return;
      }

      /* Store results  */
      (*iplist)[(*niplist)++] = ip1;
      (*iplist)[(*niplist)++] = ip2;

   } 


   free (netstr);
   free (ipstr);
   free (arg_cpy);


   /*  Correct double counting of niplist  */
   *niplist /= 2;


   /*  Print ip range  */
   if (debug_g) {
      /*  Print network ranges  */
      int i;
      printf ("\nIP Range\n");
      for (i=0;i<*niplist;i++) {
         printf ("%15s ",  ip2str((*iplist)[2*i  ]));
         printf ("%15s\n", ip2str((*iplist)[2*i+1]));
      }
      printf ("\n");
   }

}


/*  Determine if ipaddresses is within one of the ranges in iplist  */
int in_iprange (int ip, int *iplist, int niplist) {
   int i;
   for (i=0;i<2*niplist;i+=2) 
      if (ip>=iplist[i] && ip<=iplist[i+1])   return 1;
   return 0;
}


/*  Convert strings like "138.99.201.5" or "137.99.26" to int ipaddress  */
void str2ip (char *ipstr, int *ipout, int *mask) {
   int ip[4];
   int n = sscanf (ipstr, "%d.%d.%d.%d", ip, ip+1, ip+2, ip+3);
   int i;

   *ipout = 0;
   for (i=0;i<4;i++) {
      *ipout = *ipout<<8;
      if (i<n) *ipout |= (ip[i] & 0xff);
   }

   /*  Return if no net mask requested  */
   if (mask==NULL) return;

   /*  Calculate net mask  */
   *mask = 0xffffffff >> (8*n);

   /* for reasons unknown 0xffffffff >> 32 -> -1, so set to 0  */
   if (*mask==-1)  *mask=0;
}


char *ip2str (int ip) {
   static char buffer[255];
   int p[4];
   int i;
   for (i=0;i<4;i++) {
      p[i] = ip & 0xff;
      ip >>= 8;
   }
   sprintf (buffer, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
   return buffer;
}


/*  Split string of names separated by SPLIT_CHAR  */
#define SPLIT_CHAR " :"
void split (char *instr, char ***list, int *nlist) {
   char *s1, *s2;
   int n = 0;
   char *str = strdup(instr);
   /*  No input string  */
   if (*str=='\0') {
      *list = NULL;
      *nlist = 0;
      return;
   }
   /*  Count number of SPLIT_CHAR in string  */
   s1 = str;
   n=1;
   while (s2=strpbrk(s1,SPLIT_CHAR)) {
      n++;
      s1 = s2+1;
   }
   /*  Break string into substrings and store beginning  */
   *list = malloc (n*sizeof(char *));
   s1 = str;
   (*list)[0] = s1;
   n=1;
   while (s2=strpbrk(s1,SPLIT_CHAR)) {
      *(s2++) = '\0';
      (*list)[n++] = s2;
      s1  = s2+1;
   }
   *nlist = n;      
}



/*  Read options from command line  */
void read_options (int argc, char *argv[]) {
   char *t=NULL;
   char optchar;
   char *locstr, *remstr;
   while (-1 != (optchar=getopt(argc,argv,"A:CD:E:GHI:L:MN:O:PR:STV:W:bc:def:g:i:l:mo:p:qr:s:tvw:x:z:"))) {
      switch (optchar) {
      case '?':
         exit(1);
      case 'v':
         printf ("%s (compiled %s)\n", VERSION_STR, __DATE__);
         printf ("libpcap version %s\n", pcap_version);
         printf ("Default number of hash slots = %d\n", N_HASH_SLOTS);
         exit(0);
      /*  Output packet statistics in binary file format  */
      case 'b':
         strcpy (output_type_m, "BINARY");
         break;
      /*  Debugging option  */
      case 'd':
         printf ("%s (compiled %s)\n", VERSION_STR, __DATE__);
         printf ("libpcap version %s\n", pcap_version);
         printf ("Default number of hash slots = %d\n", N_HASH_SLOTS);
         debug_g = TRUE;
         break;
      /*  Print ethernet addresses if present  */
      case 'e':
         printeth_g = TRUE;
         break;
      /*  Get pcap filter string  */
      case 'f':
         filtercmd_m = strdup (optarg);
         break;
      /*  Read config file  */
      case 'g':
         set_defaults();
         read_config(optarg);
         break;
      /*  Write pid file  */
      case 'i':
         pidfile_m = fopen(optarg,"wt");
         if (NULL==pidfile_m) {
            fprintf (stderr, "ERROR:  Cannot open pidfile_m '%s'\n", optarg);
            exit(1);
         }
         fprintf (pidfile_m, "%d\n", getpid());
         fclose (pidfile_m);
         break;
      case 'x':
         progfile_m = strdup(optarg);
         break;
      case 'r':
         readfile_m = strdup(optarg);
         break;
      case 'w':
         writefile_m = strdup(optarg);
         break;
      case 'A':
         writeallfile_m = strdup(optarg);
         t=index(writeallfile_m,',');
         if (t) { 
            *t++=0; 
            ndump_all_limit_m = atoi(t); 
         } else { 
            ndump_all_limit_m = 0; 
         }
         break;
      case 'c':
         maxpkt_m    = atoi(optarg);
         break;
      case 'o':
         outfile_m   = strdup(optarg);
         break;
      case 'm':
         promisc_m   = 0;
         break;
      case 'p':
         parse_portstr(strdup(optarg));
         break;
      case 'P':
         probename_g   = TRUE;
         break;
      case 'q':
         strcpy(output_type_m, "SQL");
         break;
      case 's':
         nlen_m = atoi(optarg);
         if (nlen_m<PLEN_MIN)  
            nlen_m = PLEN_MIN;
         break;
      case 'l':
         parse_ip_range (optarg, &iplist_g, &niplist_g);
         break;
      case 'T':
         write_date_g = TRUE;
         write_time_g = TRUE;
         break;
      case 't':
         write_time_g = TRUE;
         break;
      case 'z':
         read_config_line(optarg);
         break;
      case 'C':
         useicmptype_m = TRUE;
         break;
      case 'D':
         if (atoi(optarg) == 0) {
            fork_m = FALSE;
         } else {
            fork_m = TRUE;
            dump_period_m = atoi(optarg);
         }
         break;
      case 'E':
         alarm_m = atoi(optarg);
          break;
      /*  Ignore config file  */
      case 'G':
         set_defaults();
         break;
      case 'H':
         hostonly_m = TRUE;
         break;
      case 'I':
	 sscanf (optarg, "%u.%u.%u.%u", &ip_m[0],&ip_m[1],&ip_m[2],&ip_m[3]); //Todo allow ipv6 addresses
         break;
      case 'L':
         sscanf (optarg, "%d,%d", &hostportlimit_m, &hostlimit_m);
         uselimit_m = TRUE;
         break;
      case 'M':
         allow_duplicate_m = 1;
         break;
      case 'N':
         nhashslots_m = atoi(optarg);
         if (nhashslots_m<1) {
            printf (
            "ERROR: Number of hash slots (-N%d) must be one or greater\n", 
            nhashslots_m);
            exit(1);
         }
         break;
      case 'O':
         remstr = locstr = optarg;
         while (*remstr!='\0' && *remstr!=',') remstr++;
         if (*remstr==',') *(remstr++) = '\0';
         str2ip (locstr, &iploc_m, NULL);
         str2ip (remstr, &iprem_m, NULL);
         /*  Convert from host byte order to network byte order  */
         iploc_m = htonl (iploc_m);
         iprem_m = htonl (iprem_m);
         break;
      case 'R':
         packet_sample_m = atoi(optarg);
         break;
      case 'S':
         printshort_g = TRUE;
         break;
      case 'V':
         vlan_m = atoi(optarg);
         break;
      case 'W':
         ndump_limit_m = atoi(optarg);
         break;
      default:
         exit(1);
      }
   }
}


/*  Test for space *OR* equals sign 
 *  (to allow shell scripts lines like TERM=vt1000 to be used as config
 *  files
 *  */
int is_space(char c) {
   return c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='=';
}

char *find_nonspace (char *str) {
   while (*str && is_space(*str)) str++;
   return str;
}

char *find_space (char *str) {
   while (*str && !is_space(*str)) str++;
   return str;
}


/*  Return pointers to first two space delimited tokens, 
 *  null terminating first token if necessary.
 *  If no first,second token then pointers point to '\0'
 *  Remove surround " or ' for second token
 *  */
void get_two_tok(char *str, char **tok1, char **tok2) {
   int len;

   /*  Find start of first token  */
   str = find_nonspace(str);
   *tok1 = *tok2 = str;
   if (*str=='\0') return;

   /*  Find end of first token  */
   *tok2 = str = find_space (str);
   if (*str=='\0') return;

   /*  terminate first token  */
   *(str++) = '\0';

   /*  find second token   */
   *tok2 = find_nonspace(str);

   /*  Remove trailing space  */
   str = str + strlen(str) - 1;
   while (is_space(*str)) {
      str--;
   }
   *(++str) = '\0';

   /*  Remove surrounding " or ' */
   len = strlen(*tok2);
   if (len<2) return;  /*  only one character  */
   if ( (*tok2)[0]==(*tok2)[len-1] &&
      ((*tok2)[0]=='\'' || (*tok2)[0]=='"') )
   {
      (*tok2)[len-1] = '\0';
      (*tok2)++;
   }

}

   

/*  Compare two strings ignoring case  */
int strcmpi (char *a, char *b) {
   int equal = 1;
   char c,d;
   while (equal && *a) {
      c = *a++;
      d = *b++;
      if ('a'<=c && c<='z') c += 'A' - 'a';
      if ('a'<=d && d<='z') d += 'A' - 'a';
      equal = (c==d);
   }
   if (equal) return 0;
   if (c<d)   return -1;
   return 1;
}

/*  Return true of string is yes, on, ok ignoring case  */
int is_true_str (char *str) {
   return 
      (! strcmpi("yes",str)) || 
      (! strcmpi("true",str)) ||
      (! strcmpi("on",str)) ||
      (! strcmpi("ok",str));
}



/*  Read options from config file  */
int read_config (char *filename) {
   FILE *fin = NULL;
   char buffer[512];
   int  local_errno;
   char *str;


   if (!strcmp("-",filename)) {
      fin = stdin;
   } else {
      fin = fopen (filename, "rt");
      if (NULL==fin) {         
         /*  Return a copy of errno, and reset errno=0 so that pcap_next() statement
          *  in main() will be selected to execute  */
         local_errno = errno;
         errno = 0;
         return local_errno;
      }
   }

   /*  Read lines from input file  */
   while (str=fgets(buffer, 512, fin)) {

      /*  Test for comment  */
      if (*str=='#') continue;

      read_config_line (str);
   }

   if (fin!=stdin)  fclose(fin);
}



/*  Read single configuration line  */
void read_config_line (char *str) {
   char *locstr, *remstr;
   char *t;
   char *key, *val;
   static int  use_strict=0; /*  Turn config warnings on/off  */
   int  i;

   get_two_tok(str, &key, &val);

   if (!strcmpi("debug",key)) {
      debug_g = is_true_str (val);
      if (debug_g) {
         printf ("%s (compiled %s)\n", VERSION_STR, __DATE__);
         printf ("libpcap version %s\n", pcap_version);
         printf ("Default number of hash slots = %d\n", N_HASH_SLOTS);
      }
   } else if (!strcmpi("strict",key)) {
      use_strict =  is_true_str(val);
   } else if (!strcmpi("ethernet",key)) {
      printeth_g = is_true_str(val);
   } else if (!strcmpi("filter",key)) {
      filtercmd_m = strdup(val);
   } else if (!strcmpi("pidfile",key)) {
      pidfile_m = fopen(val,"wt");
      if (NULL==pidfile_m) {
         fprintf (stderr, "ERROR:  Cannot open pidfile_m '%s'\n", val);
         exit(1);
      }
      fprintf (pidfile_m, "%d\n", getpid());
      fclose (pidfile_m);
   } else if (!strcmpi("progfile",key)) {
      progfile_m = strdup(val);
   } else if (!strcmpi("readfile",key)) {
      readfile_m = strdup(val);
   } else if (!strcmpi("writefile",key)) {
      writefile_m = strdup(val);
   } else if (!strcmpi("allfile",key)) {
      writeallfile_m = strdup(val);
      t=index(writeallfile_m,',');
      if (t) { 
         *t++=0; 
         ndump_all_limit_m = atoi(t); 
      } else { 
         ndump_all_limit_m = 0; 
      }
   } else if (!strcmpi("savefile",key)) {
      writefile_m = strdup(val);
   } else if (!strcmpi("count",key)) {
      maxpkt_m = atoi(val);
   } else if (!strcmpi("outfile",key)) {
      outfile_m = strdup(val);
   } else if (!strcmpi("promisc",key)) {
      promisc_m = is_true_str(val);
   } else if (!strcmpi("sql",key)) {
      strcpy (output_type_m, "SQL");
   } else if (!strcmpi("mysql",key)) {
      strcpy (output_type_m, "MYSQL");
      /*  Get options: host, user, password, database, 
       *  and optional table name  */
      for (i=0;i<NUM_MYSQL_OPTIONS;i++) {
         get_two_tok(val, &key, &val);
         strncpy(mysql_config_m[i], key, IP_NAME_LEN);
         /*test*/
         WRITEVAR(i,%d)
         WRITEVAR(mysql_config_m[i],%s)
         /*end test*/
      }
#ifndef USE_MYSQL
printf ("ERROR:  Cannot output to MySQL database as requested because\n");
printf ("MySQL support was not compiled into this instance of ipaudit.\n");
exit(1);
#endif
   } else if (!strcmpi("probelabel",key)) {
      strncpy(probelabel_g,val,IP_NAME_LEN);
   } else if (!strcmpi("probename",key)) {
      probename_g = is_true_str(val);
   } else if (!strcmpi("saveport",key)) {
      parse_portstr(val);
   } else if (!strcmpi("packetlen",key)) {
      nlen_m = atoi(val);
      if (nlen_m<PLEN_MIN)  nlen_m = PLEN_MIN;
   } else if (!strcmpi("localrange",key)) {
      parse_ip_range (val, &iplist_g, &niplist_g);
   } else if (!strcmpi("writetime",key)) {
      write_time_g = is_true_str(val);
      write_date_g = FALSE;
   } else if (!strcmpi("writedatetime",key)) {
      write_date_g = is_true_str(val);
      write_time_g = is_true_str(val);
   } else if (!strcmpi("icmptype",key)) {
      useicmptype_m = is_true_str(val);
   } else if (!strcmpi("hostonly",key)) {
      hostonly_m = is_true_str(val);
   } else if (!strcmpi("hostip",key)) {
      sscanf (val, "%u.%u.%u.%u", &ip_m[0],&ip_m[1],&ip_m[2],&ip_m[3]);
   } else if (!strcmpi("hostportlimit",key)) {
      sscanf (val, "%d,%d", &hostportlimit_m, &hostlimit_m);
      uselimit_m = TRUE;
   } else if (!strcmpi("allowduplicate",key)) {
      allow_duplicate_m = TRUE;
   } else if (!strcmpi("hashslots",key)) {
      nhashslots_m = atoi(val);
      if (nhashslots_m<1) {
         printf (
         "ERROR: Number of hash slots (-N%d) must be one or greater\n", 
         nhashslots_m);
         exit(1);
      }
   } else if (!strcmpi("shortip",key)) {
      printshort_g = is_true_str(val);
   } else if (!strcmpi("interface",key)) {
      read_interface_str(val);
   } else if (!strcmpi("writepacketlimit",key)) {
      ndump_limit_m = atoi(val);
   } else if (!strcmpi("daemon",key)) {
      if (atoi(val)>=0) {
         fork_m = TRUE;
         dump_period_m = atoi(val);
      } else {
         fork_m = FALSE;
      }
   } else if (!strcmpi("packetsample", key)) {
      packet_sample_m = atoi(val);
   } else if (!strcmpi("overflowip", key)) {
      remstr = locstr = val;
      while (*remstr!='\0' && *remstr!=',') remstr++;
      if (*remstr==',') *(remstr++) = '\0';
      str2ip (locstr, &iploc_m, NULL);
      str2ip (remstr, &iprem_m, NULL);
      /*  Convert from host byte order to network byte order  */
      iploc_m = htonl (iploc_m);
      iprem_m = htonl (iprem_m);
   } else if (!strcmpi("sniffinterval", key)) {
      alarm_m = atoi(val);
   } else if (!strcmpi("vlan", key)) {
      vlan_m = atoi(val);
   } else if (!strcmpi("user", key)) {
      user_m = strdup (val);
   } else if (!strcmpi("chroot", key)) {
      chroot_m = strdup (val);
   } else if (use_strict) {
      fprintf (stderr, "ipaudit: Error reading ipaudit config file. ");
      fprintf (stderr, "   Unrecognized option: \"%s\"", key);
   }
}

/*  read interface string  */
void read_interface_str (char *str) {
   /*  Split argument into interface names on ':' or ' '  */
   split (str, &pcapfilename_m, &npcapfile_m);
   /*  Allocate space for pcap file storage  */
   pcapfile_m   = malloc (npcapfile_m * sizeof(pcap_t *));
   /*  Allocate space for pcap file storage  */
   pcapoffset_m = malloc (npcapfile_m * sizeof(int     ));
}

void open_interface (void) {
   int i;
   struct bpf_program  fcode;
   char   ebuf[PCAP_ERRBUF_SIZE];

   /*   Open all files  */
   for (i=0;i<npcapfile_m;i++) {
      pcapfile_m[i] = 
         pcap_open_live(pcapfilename_m[i], nlen_m, promisc_m, 1000, ebuf);
      if (pcapfile_m[i]==NULL) {
         printf("ipaudit: Trouble opening <%s>, msg=\"%s\"  (%s)\n", 
               pcapfilename_m[i], ebuf, "Do you need root?");
         exit(1);
      }

      /*  Find packet offset  */
      pcapoffset_m[i] = get_packetoffset(pcap_datalink(pcapfile_m[i]));
      if(pcapoffset_m[i] == POFF_LINUX_SLL && printeth_g == TRUE){
	//If the packets contain SLL headers we cannot capture
	//ethernet src and dst
	printeth_g = FALSE;
	printf("Warning: ethernet headers not available.\n");
      }

      /*  Apply user requested packet filter code */
      if (pcap_compile(pcapfile_m[i], &fcode, filtercmd_m, 0, 0) < 0)
         printf("compile: %s", pcap_geterr(pcapfile_m[i]));
      if (pcap_setfilter(pcapfile_m[i], &fcode) < 0)
         printf("setfilter:  %s", pcap_geterr(pcapfile_m[i]));

      /*  Problem with pcap_setfilter?  Sets error, unset here  */
      errno = 0;
   }
}


/*  Set all options to default values (not implemented yet)  */
#define FREE(P) if ((P)!=NULL) { free(P); (P)=NULL; }
void set_defaults(void) {
   int i;

   FREE(prots_m)
   FREE(tcp_ports_m)
   FREE(udp_ports_m)
   
   
   /*  Flag for writing connection time in output  */
   write_time_g = FALSE;
   /*  Flag for printing ethernet addresses  */
   printeth_g   = FALSE;
   /*  Flag for printing IP addresses in short format  */
   printshort_g = FALSE;
   
   debug_g     = FALSE;
   
   /*  Pcap input file  */
   if (pcapfilename_m)
   for (i=0;i<npcapfile_m;i++) {
      FREE(pcapfilename_m[i])
      }
   FREE (pcapfilename_m)
   FREE (pcapfile_m)
   FREE (pcapfiletype_m)
   FREE (pcapoffset_m)
   npcapfile_m  = 0;
   
   npkt_m = 0;      /*  Number of    packets  */
   nippkt_m  = 0;   /*  Number of ip packets  */
   nconn_m   = 0;   /*  Number of connections */
   
   /*  IP address range for sorting  */
   FREE(iplist_g)
   niplist_g = 0;
   
   /*  Variables for input options  */
   strcpy (output_type_m, "TEXT");
   promisc_m       = 1;          /*  Default, set promiscuius mode */
   FREE(pidfile_m)
   FREE(progfile_m)
   FREE(writefile_m)
   FREE(writeallfile_m)
   FREE(readfile_m)
   FREE(outfile_m)
   maxpkt_m        = 0;
   hostonly_m      = FALSE;
   uselimit_m      = FALSE;
   useicmptype_m   = FALSE;
   hostportlimit_m = 0;
   hostlimit_m     = 0;
   nlen_m          = PLEN_DEF;   /*  Packet length to dump  */
   filtercmd_m     = "";
   filtercmd_m    = "";
   nhashslots_m    = N_HASH_SLOTS;
   allow_duplicate_m = 0;
   
   ip_m[0]       = 0;
}


/*--print--*/
/*  If number of stored packets with full host,port info
 *  exceeded then just store host info.  If number of packets
 *  with host info exceeded, then just increment byte and packet
 *  info with a dummy host pair 0.0.0.0 0.0.0.0   */
int impose_host_port_limit (U_CHAR * key, int keysize, int is_ip4) {

   /*  Exceeded host/port limit  */
   if (uselimit_m && nconn_m >= hostportlimit_m) {
      
     if(is_ip4){

      /*  Set both host ports to 0  */
      memset (key + KEY_SRCPT_V4, 0, 2);
      memset (key + KEY_DSTPT_V4, 0, 2);

      /*  Exceeed host-only limit also  */
      if (nconn_m >= hostportlimit_m + hostlimit_m) {
   
         /*  Set ethernet addresses to 0  */
         if (keysize>=KEY_DSTEP_V4+6) {
            memset (key + KEY_SRCEP_V4, 0, 6);
            memset (key + KEY_DSTEP_V4, 0, 6);
         }
   
         /*  Determine if addresses are local/remote  */
         if (niplist_g) {
   
            if (in_iprange (ntohl(* (int *) (key + KEY_SRCIP_V4) ), 
               iplist_g, niplist_g))
               memcpy (key + KEY_SRCIP_V4, &iploc_m, 4);
            else
               memcpy (key + KEY_SRCIP_V4, &iprem_m, 4);
   
            if (in_iprange (ntohl(* (int *) (key + KEY_DSTIP_V4) ),
               iplist_g, niplist_g))
               memcpy (key + KEY_DSTIP_V4, &iploc_m, 4);
            else
               memcpy (key + KEY_DSTIP_V4, &iprem_m, 4);
   
         /*  No local/remote configured, so set host IPs to 0.0.0.0  */
         } else {
            memset (key + KEY_SRCIP_V4, 0, 4);
            memset (key + KEY_DSTIP_V4, 0, 4);
         }
   
      }  /*  Host-only limit exceeded  */

      /*  Return value corresponding to limit was imposed */
      return 1;

     } else{

       /*  Set both host ports to 0  */
       memset (key + KEY_SRCPT_V6, 0, 2);
       memset (key + KEY_DSTPT_V6, 0, 2);

       /*  Exceeed host-only limit also  */
       if (nconn_m >= hostportlimit_m + hostlimit_m) {
   
         /*  Set ethernet addresses to 0  */
         if (keysize>=KEY_DSTEP_V6+6) {
	   memset (key + KEY_SRCEP_V6, 0, 6);
	   memset (key + KEY_DSTEP_V6, 0, 6);
         }
   
         /*  Determine if addresses are local/remote  */
         if (niplist_g) {
   
	   if (in_iprange (ntohl(* (int *) (key + KEY_SRCIP_V6) ), 
			   iplist_g, niplist_g))
	     memcpy (key + KEY_SRCIP_V6, &iploc_m, 4);
	   else
	     memcpy (key + KEY_SRCIP_V6, &iprem_m, 4);
   
	   if (in_iprange (ntohl(* (int *) (key + KEY_DSTIP_V6) ),
			   iplist_g, niplist_g))
	     memcpy (key + KEY_DSTIP_V6, &iploc_m, 4);
	   else
	     memcpy (key + KEY_DSTIP_V6, &iprem_m, 4);
   
	   /*  No local/remote configured, so set host IPs to 0.0.0.0  */
         } else {
	   memset (key + KEY_SRCIP_V6, 0, 4);
	   memset (key + KEY_DSTIP_V6, 0, 4);
         }
   
       }  /*  Host-only limit exceeded  */

       /*  Return value corresponding to limit was imposed */
       return 1;
     
     }

   } /*  Exceeded host/port limit  */

   return 0;
}
