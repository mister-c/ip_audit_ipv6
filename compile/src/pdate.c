/*
------------------------------------------------------------------------
Compile Switches
------------------------------------------------------------------------
*/
/*
------------------------------------------------------------------------
Include Files
------------------------------------------------------------------------
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */


extern int errno;

/*
------------------------------------------------------------------------
Defines
------------------------------------------------------------------------
*/
#define VERSION_STR "pdate 0.91"
#define TIME_LEN 1024


/*
------------------------------------------------------------------------
DEBUGGING MACROS
------------------------------------------------------------------------
*/
#define WRITEMSG \
	printf ("File %s line %d: ", __FILE__, __LINE__); \
	printf ("errmsg <%s>\n", strerror(errno)); fflush(stdout); 
#define WRITEVAR(VAL,FMT) \
	printf ("File %s line %d: ", __FILE__, __LINE__); \
	printf ("%s=",#VAL); printf (#FMT, VAL); printf ("\n"); \
	fflush(stdout); 


/*
------------------------------------------------------------------------
Macros
------------------------------------------------------------------------
*/
/*
------------------------------------------------------------------------
Typedefs
------------------------------------------------------------------------
*/
/*
------------------------------------------------------------------------
Global Variables
------------------------------------------------------------------------
*/
extern int daylight;

/*
------------------------------------------------------------------------
Module Wide Variables
------------------------------------------------------------------------
*/
/*
------------------------------------------------------------------------
Local Function Prototypes
------------------------------------------------------------------------
*/
void Usage(void);
long tosec (char *timestr);



/*
------------------------------------------------------------------------
Main
------------------------------------------------------------------------
*/
int main (int argc, char *argv[]) {
	char optchar;
	int  nopt=0;
	int  nscan=0;
	char *date_format    = "%Y-%m-%d-%H:%M";
	char *time_interval   = "1d";
	char *rounding_time  = NULL;
	char *initial_time   = NULL;
	char *pstr           = NULL;
	time_t current_time  = 0;
	time_t standard_time = 0;
	time_t time_diff     = 0;
	int    isdst = 0;
	struct tm *ts = NULL;
	char timestr[TIME_LEN+1];
	char *prefix="", *suffix="";
	int  ndate = 1;
	int  result;
	int  time_adjust_sec = 0;


	while (argc>1 && -1 != (optchar=getopt(argc,argv,"a:d:f:hi:n:p:r:s:t:v"))) {
		nopt++;
		switch (optchar) {
			case '?':
				return 1;
			case 'a':
				time_adjust_sec += tosec (optarg);
				break;
			/*  Use daylight savings time  */
			case 'd':
				isdst = atoi(optarg);
				break;
			case 'h':
				Usage();
				return 0;
			case 'v':
				printf ("%s (compiled %s)\n", VERSION_STR, __DATE__);
				return 0;
			case 'f':
				date_format    = strdup(optarg);
				break;
			case 'i':
				time_interval  = strdup(optarg);
				break;
			case 't':
				initial_time   = strdup(optarg);
				break;
			case 'r':
				rounding_time  = strdup(optarg);
				break;
			case 'p':
				prefix         = strdup(optarg);
				break;
			case 's':
				suffix         = strdup(optarg);
				break;
			case 'n':
				ndate          = atoi(optarg);
				break;
			default:
				return 1;
		}
	}


	/*  Read input time  */
	if (initial_time) {
		ts = (struct tm *) calloc (1, sizeof(struct tm));
		/*  Use new 'get_digits()' function  */
		pstr = initial_time;
		ts->tm_year = get_digits (&pstr, 4);
		ts->tm_mon  = get_digits (&pstr, 2);
		ts->tm_mday = get_digits (&pstr, 2);
		ts->tm_hour = get_digits (&pstr, 2);
		ts->tm_min  = get_digits (&pstr, 2);
#if 0
		/*  Old use of scanf function  */
		nscan = sscanf (initial_time, "%d-%d-%d-%d:%d", 
			&ts->tm_year,
			&ts->tm_mon,
			&ts->tm_mday,
			&ts->tm_hour,
			&ts->tm_min
		);
		if (nscan==5) {
		} else {
			if (nscan<5)  
				nscan = sscanf (initial_time, "%d-%d-%d",
				&ts->tm_year,
				&ts->tm_mon,
				&ts->tm_mday
				);
				ts->tm_hour = 0;
				ts->tm_min  = 0;
		}
		if (nscan<3) {
			perror ("Initial time is in unrecognized format\n");
			exit (1);
		}
#endif
		/*  Internal representation for year is measured from 1900  */
		ts->tm_year -= 1900;
		/*  Internal representation for month ranges from 0 to 11   */
		ts->tm_mon  -= 1;
		/*  Should we respect daylight savings time ?  */
		/*  
		For example, if isdst = -1 then for end of DST interval (2:00am Oct 29, 2000)
			`pdate -t 2000-10-29-01:30 -i30m`
		yields
			 2000-10-29-01:00
		which is 30min *before* rather than *after* (-i30m should give 30minutes after)
		Setting isdst=0 gives 'expected' value, 200-10-29-02:00
		*/
		ts->tm_isdst = isdst;
		current_time = mktime(ts);
	} else {
		current_time = time(NULL);	
	}

	/*  Round time  */
	if (rounding_time) {
		current_time -= current_time % tosec(rounding_time);
	}


	/*  Adjust time  */
	current_time  += time_adjust_sec;

	/*  Print date/time(s)  */
	while (ndate--) {
		ts = localtime(&current_time);
		result = strftime (timestr, TIME_LEN, date_format, ts);
		/* Error:  time string too long  */
		if (result==0) {
			fprintf (stderr, "ERROR: pdate could not produce the requested time string.  Either the\n");
			fprintf (stderr, "       resulting string exceeded the pre-programmed limit of %d or you\n",
					TIME_LEN);
			fprintf (stderr, "       requested a time format that yielded an empty string.\n");
			return 1;
		}
		printf ("%s%s%s", prefix, timestr, suffix);
		if (!ndate) break;
		printf (" ");
		current_time += tosec(time_interval);
	}
	printf("\n");

	/*  All done  */
	return 0;
}

/*
------------------------------------------------------------------------
Functions
------------------------------------------------------------------------
*/

/* 
Convert strings of form 10s, 21m, 102h, 7d to seconds
where letters smhd denote seconds, minutes, hours, days
*/
long tosec (char *timestr) {
	int length = strlen(timestr);
	int unitchar   = tolower (timestr[length-1]);
	long unit;
	long time;

	switch (unitchar) {
		case 'd':
			unit = 60*60*24;
			break;
		case 'h':
			unit = 60*60;
			break;
		case 'm':
			unit = 60;
			break;
		case 's':
			unit = 1;
			break;
		default:
			perror ("Invalid time unit\n");
			exit(1);
	}
	return unit * atol(timestr);
}


void Usage (void) {
	printf("\n");
	printf(" pdate [-hfinprstv]\n");
	printf("\n");
	printf("    Prints date and time.  Without arguments prints\n");
	printf("    current time in format YYYY-mm-dd-HH:MM such as\n");
	printf("       2000-08-14-01:43\n");
	printf("\n");
	printf("   -a  <a>{s|m|h|d} Adds negative or positive adjustment <a> to time.\n");
	printf("                      Append letter s,m,h,d for to use units of\n");
	printf("                      seconds, minutes, hours or days.  Multiple calls\n");
	printf("                      are cumulative.\n");
	printf("   -d  <n>          Daylight savings time - default 0\n");
	printf("                      (same as tm_isdst field in ctime command)\n");
	printf("   -h               Print help.\n");
	printf("   -i  <interval>   Interval of time for multiple date/time(s).  Format same\n");
	printf("                      as -a option.  Default value is 1d (one day)\n");
	printf("   -f  <string>     Format string for time.  See 'man strftime' for details.\n");
	printf("   -n  <ndate>      Generate <ndate> date/times each -i <interval> apart\n");
	printf("   -p  <prefix>     Prepend string <prefix> to date(s).\n");
	printf("   -s  <suffix>     Append  string <suffix> to date(s).\n");
	printf("   -r  <interval>   Round time to previous interval using same\n");
	printf("                      units as -a option above.  This is done before\n");
	printf("                      increment is added.  For example, if\n");
	printf("                      time is 12:41, the '-r 30m' option would\n");
	printf("                      round the time to 12:30\n");
	printf("   -t  <date/time>  Use specified date/time instead of current\n");
	printf("                      time, must be in format YYYY-mm-dd-HH:MM.\n");
	printf("   -v               Print version.\n");
	printf("\n");
	exit(0);
}



/*  Remove the first 'max' digits from string in buf,
 *  adn return their integer value.  Useful for 
 *  converting strings like 2003-05-07-15:05 or even
 *  200305071505 to year, month, day, hour, minute
 */
#define NTMPBUF 32
int get_digits (char **buf, int max) {
	char *p = *buf;
	char tmpbuf[32];
	int count = 0;
	/*  Skip leading non-digits  */
	while (*p && (*p<'0' || *p>'9') ) {
		p++;
	}
	/*  Read consecutive digits up to max count  */
	while (count<max && *p && *p>='0' && *p<='9') {
		if (count<NTMPBUF-1) 
			tmpbuf[count] = *p;
		count++;
		p++;
	}
	*buf = p;
	tmpbuf[count] = 0;
	return atoi(tmpbuf);
}
