#!/usr/bin/perl
# Simple commandline program to do manual IP+TCP passive OS fingerprinting
# currently only uses the IP TTL and the TCP maxwin, this should be extended
# with the pressence of a TCP slowstart, and maybe with other IP and TCP fields
# if these prove usefull.
$newttl=$ARGV[0];
$newwin=$ARGV[1];
unless (($newttl > 0) && ($newwin > 0))
{
  print " Usage:\n\n  ./tcpos.pl <ttl> <maxwindow>\n\n"; 
  exit;
}
open(PRINTS,"tcpos.conf");
while(<PRINTS>)
{
  unless (/^#/)
  {
    chomp();
    chomp();
    if (/^TTL\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)/)
    {
      $start=$1;
      $end=$2;
      $likely=$3;
      $possible=$4;
      $unlikely=$5;
      foreach $x ($start .. $end)
      {
         if ($newttl == $x)
         {
	     @LIKELY=split(/\,/,$likely);
             foreach $ttl (@LIKELY) 
	     {
		$points=$TTL{"LIKELY"};
                $TTLPOINTS{$ttl}=$points;
	     }
	     @POSSIBLE=split(/\,/,$possible);
             foreach $ttl (@POSSIBLE) 
	     {
		$points=$TTL{"POSSIBLE"};
                $TTLPOINTS{$ttl}=$points;
	     }
	     @UNLIKELY=split(/\,/,$unlikely);
             foreach $ttl (@UNLIKELY) 
	     {
		$points=$TTL{"UNLIKELY"};
                $TTLPOINTS{$ttl}=$points;
	     }
         }
      }   
    }
    elsif (/^FZY\s+(\S+)\s+(\S+)\s+(\S+)/)
    {
        $module=$1;
	$name=$2;
	$value=$3;
        if ($module eq "TTL") {$TTL{$name}=$value;}
        if ($module eq "SLOWSTART") {$SLOWSTART{$name}=$value;}
        if ($module eq "WINDOW") {$WINDOW{$name}=$value;}
    }
    elsif (/^OS\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)/)
    {
      $os=$1;
      $version=$2;
      $platform=$3;
      $full_os="$os $version ($platform)";
      $MAINOS{$full_os}=$os;
      $ttl=$4;
      $window1=$5;
      $window2=$6;
      $slowstart=$7;
      if (defined ($TTLPOINTS{$ttl}))
      {
         if ($OSTTLPOINTS{$full_os} < $TTLPOINTS{$ttl})
         {
            $OSTTLPOINTS{$full_os}=$TTLPOINTS{$ttl};
         }
      }
      else
      {
	unless (defined($OSTTLPOINTS{$full_os}))
        {
           $OSTTLPOINTS{$full_os}=$TTL{"DEFAULT"};
        }
      }
      if (($newwin >= $window1) && ($newwin <= $window2))
      {
         if ($window1 == $window2)
         {
           if ($OSWINPOINTS{$full_os} < $WINDOW{"FULL"})
           {
            $OSWINPOINTS{$full_os}=$WINDOW{"FULL"};
           }
         }
         else
         {
           if ($OSWINPOINTS{$full_os} < $WINDOW{"RANGE"})
           {
            $OSWINPOINTS{$full_os}=$WINDOW{"RANGE"};
           }
         }        
      }
      else
      {
	unless (defined($OSWINPOINTS{$full_os}))
        {
           $OSWINPOINTS{$full_os}=$WINDOW{"DEFAULT"};
        }
      }
    }
    elsif (/^FREQ\s+(\S+)\s+(\d+)/)
    {
       $OSFREQ{$1}=$2;
    }
  }
}
$bestval=-10000;
$bestos="Unknown OS";
foreach $os (keys %OSTTLPOINTS)
{
  $val=$OSTTLPOINTS{$os}+$OSWINPOINTS{$os};
  if ($val == $bestval)
  {
     $ccount++;
     $alternatives.="       *  $os\n";
     $main_os=$MAINOS{$os};
     $main_os2=$MAINOS{$bestos};
     if ($OSFREQ{$main_os} > $OSFREQ{$main_os2})
     {
       $bestval=$val;
       $bestos=$os;
     }
  }
  elsif ($val > $bestval)
  {
       $bestval=$val;
       $bestos=$os;
       $ccount=1;
       $alternatives="       *  $os\n";
  }
}
$ttl=$OSTTLPOINTS{$bestos};
$win=$OSWINPOINTS{$bestos};
$main_os=$MAINOS{$bestos};
$freq=$OSFREQ{$main_os};
print "\n\nMost likely OS: $bestos ($bestval)\n";
print "   Fzy Points for ttl: $ttl\n";
print "   Fzy Points for window: $win\n";
if ($ccount > 1)
{
	print "\n      OS Frequency  points for the $main_os OS is highest ($freq)\n";
	print "      The following complete list OSses got the same total count:\n\n$alternatives\n";

}
