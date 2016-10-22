#!/usr/bin/perl
$dumpfile=$ARGV[0];
unless ($dumpfile)
{
  print "Usage:\n\n  ./osprints.pl <tcpdumpfile>\n\n";
  exit;
}
unless ((-f $dumpfile)||($dumpfile =~ /^ppp\d+$/)||($dumpfile =~ /^eth\d+$/))
{
  print "No such file \'$dumpfile\'\n";
  exit;
}
if (($dumpfile =~ /^ppp\d+$/)||($dumpfile =~ /^eth\d+$/))
{
  open(TCPDUMP,"/usr/sbin/tcpdump -v -n -i $dumpfile|");
  $ip = $ARGV[1];
}
else
{
  open(TCPDUMP,"/usr/sbin/tcpdump -v -n -r $dumpfile|");
}
while(<TCPDUMP>)
{
  if (/^(.*):\s+S\s+.*\s+win (\d+)\s+.*ttl\s+(\d+)\,/)
  {
     $skip=0;
     if ($ip)
     {
       if ($1 =~ /$ip.*\>/) {$skip=1;}
     }
     unless ($skip)
     {
     	$intro=$1;
     	$win=$2;
     	$ttl=$3;
     	print "$intro : $win $ttl\n";
     	open(TCPOS,"./tcpos.pl $ttl $win|");
     	while(<TCPOS>)
     	{
     	  if (/\w+/)
     	  {
     	    print "   $_";
     	  }
     	}
     	close(TCPOS);
     }
  }
}
