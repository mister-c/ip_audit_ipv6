package ipaudit_config;

use 5.004;
use strict;
use warnings;

BEGIN {
  use Exporter;
  use vars qw($VERSION $IPAUDITCONF @ISA @EXPORT @EXPORT_OK);

  $VERSION = '0.04';
  @ISA = qw(Exporter);
  @EXPORT_OK = qw(&ipa_scrub);
  @EXPORT = qw(&ipa_getconf);

  ###############################################################
  ### Change IPAUDITCONF to where ipaudit-web.conf is located.###
  ### This can also be changed via "make adjust-cgi" after    ###
  ### ./configure has been run.				      ###
  ###############################################################
  $IPAUDITCONF = "/home/ipaudit/ipaudit-web.conf";
}

# This would be set in whatever perl script is calling us.
use vars qw($DEBUG);

sub ipa_getconf() {
  my $Value;
  my $Name;
  my %Conf;
  open(IPAUDITCONF, "<$IPAUDITCONF") or die "Can't Open $IPAUDITCONF: $!\n";
  while(<IPAUDITCONF>)
  {
    next if $_ =~ /^#/ || $_ =~ /^\s*\n$/; # skip comments, blanks and newlines.
    ($Name,$Value) = split(/=\s*/);        # this outta grab variables with spaces in 'em, ie: GNUPLOT
    $Name =~ s/\s//g;			   # tidy up var names with spaces infront or behind.
    $Value =~ s/"|'//g;                    # more tidy with " and '
    chomp($Conf{uc $Name} = $Value);
  }
  close(IPAUDITCONF);
  if($DEBUG) {
    print("DEBUG (ipaudit_config_getconf) $IPAUDITCONF read OK\n") if $DEBUG;
    foreach my $keys (keys %Conf) {
      print("DEBUG (ipaudit_config_getconf) $keys -> $Conf{$keys}\n");
    }
  }
  return(%Conf);
}

sub ipa_scrub($$) {
  my $type = "$_[0]";
  my $data = "$_[1]";
  my %scrub_as;

  %scrub_as = (
    "dir"  , '([\/\w-]+)',
    "ip"   , '([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})',
    "word" , '([A-Za-z_-]+)',
    "digit", '([\d]+)'
  );

  if(!$scrub_as{$type}) { 
    print("DEBUG (ipaudit_config_scrub) switching to user-defined regex (unknown type)\n") if $DEBUG; 
    $scrub_as{$type} = "($type)";
  } else {
    print("DEBUG (ipaudit_config_scrub) type: $type\n") if $DEBUG;
  }
  print("DEBUG (ipaudit_config_scrub) data: $data\n") if $DEBUG;
  print("DEBUG (ipaudit_config_scrub) scrub_as regex: $scrub_as{$type}\n") if $DEBUG;
  if("$data" =~ /^$scrub_as{$type}$/) {
    print("DEBUG (ipaudit_config_scrub) regex OK\n") if $DEBUG;
    return($1);
  } else {
    print("DEBUG (ipaudit_config_scrub) regex FAIL\n") if $DEBUG;
    return undef;
  }
}

1;
__END__

=head1 NAME

B<ipaudit_config.pm> v0.04

Reads configuration info needed by Ipaudit CGI and other scripts. 
This module also performs some other sundry duties, such as variable scrubbing.

=head1 SYNOPSIS

	#!/usr/bin/perl

	BEGIN {
	  unshift (@INC,"/path/to/ipaudit_config.pm/directory/");
	}

	# note CAPITAL {VARS} below

B<0.03 method:> (still valid)

	use ipaudit_config;
	%conf = ipa_getconf; # assign vars
	$zgrep = $conf{'ZGREP'} || do_something_special;

B<0.04 method:>

	use ipaudit_config; # import all our variables from the conf
	use ipaudit_config(ipa_scrub) # I want our scrubber, too
	%conf = ipa_getconf; # assign vars
	# Be sure zgrep is in the form of /<path>/<binary>
	$zgrep = ipa_scrub("dir","$conf{'ZGREP'}"); || do_something_special;

=head1 DESCRIPTION

Using B<use ipaudit_config()> will import ONLY the variables parsed from B<ipaudit-web.conf>.
Everything else must be explicitly imported.

=head2 EXPORT

B<ipa_getconf>	Returns a hash of variables. Takes no arguments.

B<ipa_scrub>("I<type>","I<input>")	Scrubs variables. ipa_scrub() currently has four default scrubbing I<type> profiles:

B<	dir>		directory scrub: [\/\w-]+

B<	ip>		ip address scrub: [\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}

B<	word>		word scrub: [A-Za-z_-]+ 

B<	digit>	digit scrub: [\d]+

If I<type> is not one of the above, ipa_scrub() will use I<type> as a user-defined regex and check I<input> against that regex. All regexs are anchored with ^ and $.

B<$ipaudit_config::IPAUDITCONF>	Location of the config file.

=head1 DEBUGING

ipaudit_config() has a debug mode that can be enabled inside a PERL script with:

B<$ipaudit_config::DEBUG = 1;>

admittedly, there really isn't much to see with this option however.

=head1 BUGS

Probably. Regexs might could also be more strict, but I think it should be fine as is. This module will probably need to be renamed soon as well - it has outgrown its original purpose.

=head1 SEE ALSO

ipaudit(1), ipstrings(1), total(1)

=head1 CHANGELOG

v0.01, 01/19/02:
  - Initial module

v0.02, 01/31/02:
  - Rewrote parsing engine to appropriately handle
    variables that include spaces.
  - Variable normalizing.
  - Updated SYNOPSIS.

v0.03, 02/04/02:
  - Overlooked the "use 5.006" - Such a new version isn't
    really needed, so it was changed to 5.004.
  - Moved "our" stuff into "use vars." Not really needed,
    and enables this to be used on older versions of perl.

v0.04, 10/15/03:
  - Trying to consolidate reusable code - module now does
    variable scrubbing, and whatever else we deem reusable.
  - Debugging code was added for whatever reason you can
    come up with - bonus points for something creative.
  - Some code reorganization.

=head1 AUTHOR

jh <jh@dok.org> Use and redistribution allowed at user's own
risk.

=cut
