# GOALS
#     1) install either new installation or upgrade with same commands
#           (make ipaudit user)
#           ./configure
#           make
#           su root
#           make install
#           make install-cron
#           vi ~ipaudit/ipaudit-web.conf (set LOCALRANGE)
#      2) Error message, check when a) no ipaudit user b) not root
#      
# CHANGES
#   1) add an 'install-files' clause that's called from 'install'.
#   2) move 'make install' clauses root user test and /home/ipaudit test
#      to their own clause called 'install-test'.
#   3) made local vars $(user) $(group), hard coded to ipaudit/ipaudit.
#      to facilitate future --with-user --with-group ./configure options?
#   4) pipe error output for 'crontab -l' to /dev/null to avoid
#      possible error message if not pre-existing crontab entries.
#   5) in 'install-cron' add 'cd ~/' to insure running from ipaudit's
#      home directory
#   6) add explicit messages to next step in sequence, 'make', 
#      'make install', 'make install-cron', and configure LOCALRANGE 
#      in 'ipaudit-web.conf'
#
#

dist_subdirs =	src
inc_subdirs =	
subdirs =	$(dist_subdirs) $(inc_subdirs)
top_srcdir =	.
srcdir =	.
MAKE =		make
user =          ipaudit
group =         ipaudit

#  List of directories to create if not already present
dirs =	bin \
	cron \
	data \
	data/30min \
	data/30min/localhost \
	data/daily \
	data/daily/localhost \
	data/monthly \
	data/monthly/localhost \
	data/weekly \
	data/weekly/localhost \
	man \
	man/man1 \
	man/man3 \
	public_html \
	public_html/cgi-bin \
	public_html/images \
	raw \
	raw/30min \
	reports \
	reports/30min \
	reports/30min/0traffic \
	reports/30min/0traffic/html \
	reports/30min/graphic \
	reports/daily \
	reports/daily/server2 \
	reports/daily/server2/html \
	reports/daily/traffic \
	reports/daily/traffic/html \
	reports/daily/type \
	reports/daily/type/html \
	reports/monthly \
	reports/monthly/traffic \
	reports/monthly/traffic/html \
	reports/weekly \
	reports/weekly/traffic \
	reports/weekly/traffic/html \
	run \
	tmp

#  List of directories to copy from install tree to production tree
copydirs = bin cron man public_html reports

all:
	target=`echo $@`; \
	list='$(subdirs)'; for subdir in $$list; do \
	echo "Making $$target in $$subdir"; \
	(cd $$subdir && $(MAKE)); \
	done
	@echo
	@echo "**************************************"
	@echo "  Now, as ROOT,  run 'make install'  "
	@echo "**************************************"
	@echo


clean:
	target=`echo $@`; \
	list='$(subdirs)'; for subdir in $$list; do \
	echo "Making $$target in $$subdir"; \
	(cd $$subdir && $(MAKE) clean); \
	done; 
#	@echo "Cleaning out stale pid file"
#	rm -f run/ipaudit.pid


make-dirs:
	@for i in $(dirs) ; do \
	if [ ! -d /home/ipaudit/$$i ] ; then \
		mkdir /home/ipaudit/$$i; \
		chown $(user) /home/ipaudit/$$i; \
		chgrp $(group) /home/ipaudit/$$i; \
	fi; \
	done


#  Remove all crontab entries which run from cron/ directory
clean-cron:
	@echo \* This crontab install should be enough cross-platform to complete successfully.
	@echo If there are errors or suggestions, mail jh at dok.org.
	su $(user) -c 'cd ~/; crontab -l | grep -v cron/cron | grep -v ^\# | cat > `pwd`/cron-clean.tmp \
	&& crontab cron-clean.tmp && rm -f "cron-clean.tmp"'


distclean: clean
	rm -f Makefile config.cache config.log config.status config.h src/Makefile
	target=`echo $@`; \
	list='$(inc_subdirs)'; for inc_subdir in $$list; do \
	echo "Making $$target in $$inc_subdir"; \
	(cd $$inc_subdir && $(MAKE) distclean); \
	done;


#  Test for conditions before install
install-test: 
	@if [ `/usr/bin/id -u` != "0" ]; then echo; \
	echo "*****************************************"; \
	echo "   This install should be run as ROOT."; \
	echo "*****************************************"; \
	echo; \
	exit 1; fi
	@if [ -z "/home/ipaudit" ]; then echo; \
	echo "***********************************************************";  \
	echo "  Can't install: No idea where ipaudit's home is located.";  \
	echo "***********************************************************";  \
	echo; \
	exit 1; fi


#  Run install as root
install: install-test make-dirs adjust-cgi install-files
	@echo "Installing IPaudit binaries..."
	/usr/bin/install -c -o $(user) -g $(group) -m 755 src/ipstrings /home/ipaudit/bin
	/usr/bin/install -c -o $(user) -g $(group) -m 755 src/makelocal /home/ipaudit/bin
	/usr/bin/install -c -o $(user) -g $(group) -m 755 src/total /home/ipaudit/bin
	/usr/bin/install -c -o $(user) -g $(group) -m 755 src/pdate /home/ipaudit/bin
	/usr/bin/install -c -o $(user) -g $(group) -m 755 src/calcbytes /home/ipaudit/bin
	/usr/bin/install -c -o $(user) -g $(group) -m 755 src/lookforzero /home/ipaudit/bin
	#  make ipaudit suid root
	@echo "Installing ipaudit binary setid root"
	/usr/bin/install -c -o root -g $(group) -m 4750 src/ipaudit /home/ipaudit/bin
	@echo
	@echo "Making home and public_html directory accessible by http"
	chmod 711 /home/ipaudit 
	chmod 755 /home/ipaudit/public_html
	@#Shouldn't do this now, we may be installing into a live tree.
	@#@echo "Cleaning out any stale pid file"
	@#rm -f run/ipaudit.pid
	@#@echo "Preparing empty directories"
	@#su ipaudit -c 'bin/create_dir'
	@echo "Insuring cgi-bin dir and scripts are not group writable,"
	@echo "otherwise Apache suexec will refuse to run them"
	chmod g-w /home/ipaudit/public_html/cgi-bin /home/ipaudit/public_html/cgi-bin/*
	@#This doesn't exist if configure already detected a pre-existing conf in /home/ipaudit
	@#ipaudit-web.conf won't exist during install if configure detected a pre-existing conf in /home/ipaudit/
	#  Install confs
	if [ ! -f "/home/ipaudit/ipaudit-web.conf" ]; then \
		if [ ! -f ./ipaudit-web.conf ]; then \
			echo "*** Couldn't find ./ipaudit-web.conf in source. Run ./configure?"; \
			exit 1; \
		fi; \
		echo "*** Installing ipaudit-web.conf into /home/ipaudit"; \
	        /usr/bin/install -c -o $(user) -g $(group) -m 640 ./ipaudit-web.conf /home/ipaudit; \
	else \
		echo "*** Skipping ipaudit-web.conf install: existing /home/ipaudit/ipaudit-web.conf detected."; \
	fi;
	@echo "*** Installing ipaudit_config.pm into /home/ipaudit"
	/usr/bin/install -c -o $(user) -g $(group) -m 644 ../ipaudit_config.pm /home/ipaudit/

# The below functionality moved to configure --jh
#  Install ipaudit-web.conf (backup any previous ipaudit-web.conf)
# if [ -w ipaudit-web.conf ]; then mv ipaudit-web.conf ipaudit-web.conf.`bin/pdate`; fi
# /usr/bin/install -c -o $(user) -g $(group) -m 644 ipaudit-web.conf.install ipaudit-web.conf
	@echo
	@echo "Installing any --enabled packages now..."
	target=`echo $@`; \
	list='$(inc_subdirs)'; for inc_subdir in $$list; do \
	echo "Making $$target in $$inc_subdir"; \
	(cd $$inc_subdir && $(MAKE) $$target); \
	done
	@echo
	@echo "*******************************************"
	@echo "  Now,  as ROOT,  run 'make install-cron'  "
	@echo "********************************************"
	@echo


#  Append crontab.install to existing crontab minus ~/ipaudit/cron/*
install-cron:
	@echo \* This crontab install should be enough cross-platform to complete successfully.
	@echo If there are errors or suggestions, mail jh at dok.org.
	@echo
	su ipaudit -c '  \
		cd ~/;  \
		crontab -l 2> /dev/null |  \
			grep -v cron/cron |  \
			grep -v ^# > cron-install.tmp;   \
		cat cron/crontab.install >> cron-install.tmp; \
		crontab cron-install.tmp; \
		rm -f cron-install.tmp ' 
	@echo
	@echo "******************************************************"
	@echo "  Now set LOCALRANGE in /home/ipaudit/ipaudit-web.conf "
	@echo "  and your installation is complete.                   "
	@echo "*****************************************************"
	@echo


# This will adjust all the CGIs @INC search path to point to ipaudit's homedir
# and setup the path for ipaudit-web.conf correctly in the config perl module.
# This may not actually be necessary, if you are using the default, /home/ipaudit.
# The homedir (IPA_HOMEDIR), is autodetected from configure.
adjust-cgi:
	@if [ "/home/ipaudit" != "/home/ipaudit/" ]; then \
		if [ -z "/home/ipaudit" ]; then \
			echo "Can't adjust without a known homedir"; \
			exit 1; \
		fi; \
		echo "Adjusting homedir with /home/ipaudit for:"; \
		echo "  public_html/cgi-bin/*"; \
	  	perl -pi -e 's!^(\s*unshift \(\@INC,\s*")[\/\w\-\.]+("\)\;).*!$$1/home/ipaudit/$$2 # Adjusted via adjust-cgi!' `find ../public_html/cgi-bin/ -type f -print -o -name CVS -prune`; \
		echo "  ipaudit_config.pm"; \
	  	perl -pi -e 's!^(\s*\$$IPAUDITCONF\s*=\s*")[\/\w\-\.]+\/(ipaudit-web.conf"\;).*!$$1/home/ipaudit/$$2 # Adjusted via adjust-cgi!' ../ipaudit_config.pm; \
	 fi;

#  Copy files from install tree to production home
install-files:
	@echo "Copy files from install tree to production tree /home/ipaudit"
	@cd ..; for i in $(copydirs) ; do \
		find $$i -type f -print -o -name CVS -prune| while read a; do \
			/usr/bin/install -c -o $(user) -g $(group) $$a /home/ipaudit/$$a; done; \
	done; cd compile
