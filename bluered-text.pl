#!/usr/bin/perl
#BlueRed webapp fuzzer
# by m0nad [at] email.com
#
#BlueRed is a automated web application fuzzer. 
#its based on others open-source fuzzers like :
#powerfuzzer, wapiti, cfuzz, etc...
#Bluered 'crawl' the web site and inject payloads
#to see if the applications is vulnerable.
#Its can detect :
#local and remote file inclusions, 
#cross site scripting,
#sql injections,
#eval injections,
#and command execution.
#
#Requeride Modules:
#URI
#Getopt::Long
#LWP::UserAgent
#WWW::Mechanize
#IO::Socket::SSL (for https)
#Tk
#
#Installing:
#sudo apt-get install perl-tk
#cpan -i WWW::Mechanize
#cpan -i IO::Socket::SSL
#
#Copyright (C) 2010  Victor N. Ramos Mello
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Affero General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the GNU Affero General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.
#    
#This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
#This is free software, and you are welcome to redistribute it
#under certain conditions; type `show c' for details.

require "bluered-core.pl";
use strict; use warnings; use diagnostics;
use Getopt::Long;
my $opt = {};
my $url;


sub textopt
{  
  GetOptions(
    "url=s"		=> \$url,
    "lfi"		=> \$opt->{lfi},
    "rfi"		=> \$opt->{rfi},
    "sql"		=> \$opt->{sql},
    "xss"		=> \$opt->{xss},
    "eval"		=> \$opt->{eval},
    "cmd"		=> \$opt->{cmd},
    "all"		=> \$opt->{all},
    "out=s"		=> \$opt->{outfile},
    "double_encode"	=> \$opt->{double_encode},
    "verbose"		=> \$opt->{verbose}

  ) ;



}

sub clear()
{
 system $^O eq 'MSWin32' ? 'cls' : 'clear';
}
sub uso()
{

  print "perl $0 --url http://url/ [options]\n";
  print <<HELP;
	--verbose		Verbose mode
        --lfi			Local file include/disclosure detection
	--rfi			Remote file include/read detection
        --sql			Sql injection detection
        --xss			XSS detection
	--eval			Eval injection detection (only *nix)
	--cmd			Command execution detection (only *nix)
	--all			Detect all (default)
	--out			Set file to append results (default _vuln_bluered)
        --double_encode		Double encode (experimental)
	--help			This menu
   ex:
	perl $0 --url http://site.com/ 
	perl $0 --url http://site.com/ --sql --xss --out vulns.txt
	perl $0 --url http://site.com/ --eval --cmd --rfi --verbose
	perl $0 --url http://site.com/ --verbose
HELP
  exit;
}
sub banner()
{
  #clear();
  print '-' x 37, "\n";
  print "\tBlueRed - webfuzzer\n";
  print '-' x 37, "\n";
  print "\tm0nad [at] email [dot] com\n\n";

}
banner();
textopt();
uso() unless $url ;
_print ($opt,  "\nAttacking URL's:\n\n") ;
crawfuzz_loop($opt, [$url]);
