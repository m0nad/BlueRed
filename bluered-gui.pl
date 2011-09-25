#!/usr/bin/perl
#BlueRed webapp fuzzer
# by m0nad [at] email.com
#Original Tk GUI 
# by c00f3r[at]gmail.com
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
use warnings;
use strict;
use diagnostics;

use Tk;

my $opt;
my $url;

main();


sub main
{
	
  my $mw = MainWindow->new(-background => "white",
                        -foreground => "blue");
  $mw->geometry('480x300');
 
  $mw->title("BlueRed");
  
  $mw->Photo('logo', -file => "bluered.gif");
  $mw->Label(-image => 'logo',
	    -background => "white",
            -foreground => "blue"
            )->pack;


  my $tf = $mw->Frame(
	-background => "white"
	)->pack(
	-side => 'top',
	-anchor => 'n',
	);


 
  $tf->Label(
	-background => "white",
	-foreground => "blue",  
	-text => 'Target :',
	)->pack(
	-side => 'left'
	);
  my $host = $tf->Entry(
	-background => "white", 
	-foreground => "black", 
	-text => 'http://127.0.0.1',
	-width => 40
	)->pack(
	-side => 'left'
	);

  $tf->Button(-text => 'Fuzz',
            -relief => 'groove',
	    -command => [\&console, $host]
	)->pack(
	-side => 'left',
	);


  $mw->Button(
        -relief => 'groove',
        -text => 'Options',
        -background => "white",
        -foreground => "blue",
        -command => \&options
    	)->pack(-side => 'left',
		-anchor => 'ne',
		-expand => 1 );

  $mw->Button(
        -relief => 'groove',
        -text => 'Credits',
        -background => "white",
        -foreground => "blue",
        -command => \&creditos
    	)->pack(-side => 'left',
 		-anchor => 'nw',
		-expand => 1);
}


sub console
{
  my $host = shift;
  $url = $host->get();


  my $mw = MainWindow->new;
  $mw->geometry("100x25");
  $mw->title("BlueRed");
  $mw->Label(-relief => 'groove',
           -text =>  "Verbose Console")->pack;
  $mw->Button(-relief => 'groove',
             -text    => 'Stop',
             -command =>  [$mw => 'destroy']
             )->pack;
  my $box = $mw->Listbox(-selectmode => "browse",
                        -relief => 'sunken',
                        -background => "white",
                        -foreground => "blue",
                        -height  => 40,
                        -width => 45,
                        -setgrid => 5,
                        )->pack;

  $box->insert('end', "Attacking URL's")   ;  
     

  
  my $scroll = $mw->Scrollbar(-command => ['yview', $box]);
  $box->configure(-yscrollcommand => ['set', $scroll]);
  $box->pack(-side => 'left',-fill => 'both', -expand => 1);
  $scroll->pack(-side => 'left', -fill => 'y');

  $opt->{box} = $box;
  
  $box->after(350,[\&crawfuzz_recursive, $opt, [$url]]);

}
sub options
{

 my $mw = MainWindow->new( -background => "white",
                        -foreground => "blue",
                        -title => 'Options');
 $mw->geometry('230x250');
 
 my $frame = $mw->Frame(
	-background => "white"
	)->pack;

 $frame->Checkbutton(-text => 'Verbose mode', 
                  -background => "white",
                  -foreground => "blue", 
                  -onvalue => '--verbose',
                  -variable => \$opt->{verbose},   
        	  )->pack(
        	  -anchor => 'w',
        	  -fill => 'y'
        	  );
     


 $frame->Checkbutton(-text => 'Local File Inclusion', 
                  -background => "white",
                  -foreground => "blue", 
                  -onvalue => '--lfi',
                  -variable => \$opt->{lfi},     
        	  )->pack(
        	  -anchor => 'w',
        	  -fill => 'y'
        	  );
     
 $frame->Checkbutton(-text => 'Remote File Inclusion', 
                  -background => "white",
                  -foreground => "blue", 
                  -onvalue => '--rfi',
                  -variable => \$opt->{rfi},     
                  -offvalue => ''
                  )->pack(
        	  -anchor => 'w',
        	  -fill => 'y'
        	  );
 $frame->Checkbutton(-text => 'SQL Injection', 
                  -background => "white",
                  -foreground => "blue", 
                  -onvalue => '--sql',
                  -variable => \$opt->{sql},     
        	  )->pack(
        	  -anchor => 'w',
        
        	  );
 $frame->Checkbutton(-text => 'Cross Site Scripting', 
                  -background => "white",
                  -foreground => "blue", 
                  -onvalue => '--xss',
                  -variable => \$opt->{xss},     
        	  )->pack(
        	  -anchor => 'w',
        	  -fill => 'y'
        	  );
 $frame->Checkbutton(-text => 'Eval Injection', 
                  -background => "white",
                  -foreground => "blue", 
                  -onvalue => '--eval',
                  -variable => \$opt->{eval},     
        	  )->pack(
         	  -anchor => 'nw',	  
        	  -fill => 'y'
        	  );
 $frame->Checkbutton(-text => 'Command execution', 
                  -background => "white",
                  -foreground => "blue", 
                  -onvalue => '--cmd',
                  -variable => \$opt->{cmd},     
        	  )->pack(
         	  -anchor => 'nw',	  
        	  -fill => 'y'
        	  );
 $frame->Label(-text => 'Encoders',
            -background => "white",
            -foreground => "blue", 
            )->pack;

 $frame->Checkbutton(-text => 'Double Encode',
                  -background => "white",
                  -foreground => "blue",  
                  -onvalue => '--double_encode',
                  -variable => \$opt->{double},     
        	  )->pack(
        	  -anchor => 'nw',
        	  -fill => 'y'
        	  );
 $frame->Button(-relief => 'groove',
	     -text => 'Close',
	     -command => [$mw => 'destroy']
             )->pack;
}

sub creditos 
{

  my $mw = MainWindow->new(-background => "white",
                           -foreground => "blue",
                           -title => 'Credits');
  my $texto =
  "BlueRed by m0nad, GUI by Cooler_
  
  contact : 
  m0nad[at]email.com
  c00f3r[at]gmail.com
  from BugSec Team
  -----------
  No pain no Gain ;)";

  $mw->title ("BlueRed");

  $mw->Label(-relief => 'groove',
             -background => "white",
             -foreground => "blue", 
             -text => $texto)->pack;
  $mw->Button(-relief => 'groove',
	      -text => 'Close',
	      -command => [$mw => 'destroy']
              )->pack;

}

MainLoop;
