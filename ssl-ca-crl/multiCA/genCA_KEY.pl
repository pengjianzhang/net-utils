#!/usr/bin/perl -w

sub print_msg()
{

	print ("cn anhui hefei banggoo host:hostrootca|hostl1ca|hostl2ca|hostcase1 jzpeng\@banggoo.cn 1111 1111\n");
}

#input: name
#output: name/name.crt
#	 name/name.key
#	name/ 	dir and files for CA
	
sub create_rootCA
{

	my ($name) = @_;

	my $ROOTCA_CRT = "$name/$name.crt";
	my $ROOTCA_KEY = "$name/private/$name.key";

	`rm -rf $name; mkdir $name`; 

	print "create root CA\n";
	print "passwd: rootca\n";

	`mkdir -p $name/{private,newcerts}`;
	`touch $name/index.txt`;
	`echo 01 >  $name/serial`;
	`openssl genrsa -des3 -out $ROOTCA_KEY  2048`;
	`openssl req -new -x509 -days 3650 -key $ROOTCA_KEY -out $ROOTCA_CRT`;
	`cp $ROOTCA_KEY $name/$name.key`;
}


sub create_crt_key
{

	my ($name, $upname, $isCA) = @_;
	my $crt = "$name/$name.crt";
	my $key = "$name/$name.key";
	my $csr = "$name/$name.csr";
	 
	my $upCRT = "$upname/$upname.crt";
	my $upKEY = "$upname/$upname.key";

	print "create sub CA \n";
	print "passwd: $name\n";
	`rm -rf $name; mkdir $name`;
	`openssl genrsa -des3 -out $key 2048`;
	`openssl rsa -in $key  -out $key `;
	`openssl req -new -days 3650 -key $key  -out $csr`;

	if($isCA > 0 ){
		`openssl ca -extensions v3_ca -in $csr -config ./openssl.cnf -days 3000 -out $crt -cert $upCRT  -keyfile $upKEY `;
	}
	else{
		`openssl ca -in $csr -config ./openssl.cnf -days 3000 -out $crt -cert $upCRT  -keyfile $upKEY `;
	}
}



sub create_subCA
{
	my ($thisname, $upname) = @_;
	create_crt_key($thisname, $upname,1);
}


sub create_case
{
	my ($thisname, $upname) = @_;
	create_crt_key($thisname, $upname,0);
}


sub make_chain
{
	my $name;
	my $chainDir = "chain";
	my $chainFile = "chain.pem";

	`rm -rf $chainDir  $chainFile; mkdir $chainDir `;

	foreach  $name ( @_) {
		print "$name\n";

		`cp $name/$name.crt $chainDir/$name.pem`;	
		`cat $name/$name.crt >> $chainFile`;
	} 

	`cd $chainDir; c_rehash .`;

}

sub gen_crl
{

	my ($name) = @_;
	
	`openssl ca -revoke $name/$name.crt  -config ./openssl.cnf `;
	`openssl ca -gencrl -out  $name/crl_$name.pem  -config ./openssl.cnf   `;
}

sub run
{
	
	print_msg();

#	create_rootCA("rootCA");

#	create_subCA("l1ca", "rootCA");
#	create_subCA("l2ca", "l1ca");

#	create_case("case1","l2ca");
#	create_case("case2","l2ca");

#	create_case("rootcase3","rootCA");
#	create_case("rootcase4","rootCA");
	create_case("rootcase5","rootCA");
#	create_case("rootcase6","rootCA");


#	gen_crl("rootcase3");
	
#	gen_crl("rootcase4");
#	gen_crl("rootcase5");


#	make_chain("rootCA","l1ca","l2ca");
}


run();
