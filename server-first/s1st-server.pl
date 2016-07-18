#!/usr/bin/perl -w

use IO::Socket::INET;

$| = 1;

sub usage
{
	print ("Usage:\n\t./s1st-server.pl  PORT\n\n");
}

sub run_server
{
	my $msg = "welcome from server with server-fist protocol";
	my $data;

	my ($port) = @_;
	my $sk = new IO::Socket::INET->new(LocalHost =>"0.0.0.0", LocalPort => "$port", Type => SOCK_STREAM, Reuse => 1, Listen => 10, Blocking => 1)  or die "ERROR TCP" ;

	while(1){
                my $newfd = $sk->accept();

                if($newfd > 0)  {
			print "Accept OK\n";

			$newfd->send($msg);

			$newfd->recv($data, 1024);
			print "$data\n\n";
			$newfd->close;

                }else{
			print "Accept Error\n";
		}
	}
}



if( scalar @ARGV != 1){

	usage();
	exit 1;
}
else{
	print "running sever at port $ARGV[0] \n";
	run_server($ARGV[0]);
}
