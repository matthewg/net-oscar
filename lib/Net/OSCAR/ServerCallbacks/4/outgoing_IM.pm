package Net::OSCAR::Callbacks;
use strict;
use warnings;
use vars qw($SESSIONS $SCREENNAMES %COOKIES $screenname $connection $snac $conntype $family $subtype $data $reqid $reqdata $session $protobit %data);
sub {

$connection->proto_send(reqid => $reqid, protobit => "IM_acknowledgement", protodata => {
	cookie => $data{cookie},
	channel => $data{channel},
	screenname => $data{screenname}
});

};

