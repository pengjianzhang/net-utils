#!/usr/bin/perl -w

use IO::Socket::INET;

# auto-flush on socket
$| = 1;


sub usage
{
	print "Usage:\n\t./client Server-IP Server-Port \n\n";
}

sub run_client
{
	my ($ip,$port) = @_;

	# create a connecting socket
	my $socket = new IO::Socket::INET (
	    PeerHost => $ip,
	    PeerPort => $port,
	    Proto => 'tcp',
	);
	die "cannot connect to the server $!\n" unless $socket;

	print "connected to the server\n";

	# data to send to a server
	my $req = 'hello world from client to server after receive data from server';
	$socket->recv($response, 1024);
	print "$response\n\n";

	my $size = $socket->send($req);

	$socket->close();
}




if( scalar @ARGV != 2){

	usage();
	exit 1;
}
else{
	run_client($ARGV[0],$ARGV[1]);
}
