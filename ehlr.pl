#! /usr/bin/perl


use strict;
use IO::Socket;
use Config;

my $src_host = '192.168.100.198';
my $src_port = 2906;
my $dst_host = '192.168.100.197';
my $dst_port = 2905;

my $srism_imsi		= '52077224007353f2';
my $srism_location	= '9479010001';
my $sri_error		= ''; # '' for MSRN, '1b' for AbsentSubscriber
my $sri_imsi		= '52077224007353f2';
my $sri_msrn		= '9479020020f0';
my $ati_error		= ''; # '' for VLR, '-' for silence
my $fsm_hack		= 0;
my $idp_hack		= 0;

my $sctp_fh;
my $m3ua_rc;

my %SCTP_PAYLOAD = (
	IUA		=> 1,
	M2UA		=> 2,
	M3UA		=> 3,
	SUA		=> 4,
	M2PA		=> 5,
	V5UA		=> 6,
);

my %SCCP_TYPE = (
	CR	=> 1,
	CC	=> 2,
	CREF	=> 3,
	RLSD	=> 4,
	RLC	=> 5,
	AK	=> 8,
	UDT	=> 9,
	UDTS	=> 10,
	ED	=> 11,
	EA	=> 12,
	RSR	=> 13,
	RSC	=> 14,
	ERR	=> 15,
	IT	=> 16,
	XUDT	=> 17,
	XUDS	=> 18,
);

my %M3UA_SSNM = (
	DUNA	=> 1,
	DAVA	=> 2,
	DAUD	=> 3,
	SCON	=> 4,
	DUPU	=> 5,
	DRST	=> 6,
);

my %ASN1_UNIVERSAL = (
	boolean		=> 1,
	integer		=> 2,
	bitStr		=> 3,
	octetStr	=> 4,
	null		=> 5,
	objectId	=> 6,
	real		=> 9,
	enumerated	=> 10,
	relative_oid	=> 13,
	sequence	=> 16,
	set		=> 17,
	printStr	=> 19,
	ia5Str		=> 22,
	utcTime		=> 23,
	generalTime	=> 24,
);

my %TCAP_TYPE = reverse (
	unidirectional	=> 1,
	begin		=> 2,
	end		=> 4,
	continue	=> 5,
	abort		=> 7,
);

my %TCAP_COMPONENT = reverse (
	invoke			=> 1,
	returnResultLast	=> 2,
	returnError		=> 3,
	reject			=> 4,
	returnResultNotLast	=> 7,
);

my %GSMMAP_APP = reverse (
	networkLocUp			=> 1,
	locationCancellation		=> 2,
	roamingNumberEnquiry		=> 3,
	istAlerting			=> 4,
	locationInfoRetrieval		=> 5,
	callControlTransfer		=> 6,
	reporting			=> 7,
	callCompletion			=> 8,
	serviceTermination		=> 9,
	reset				=> 10,
	handoverControl			=> 11,
	sIWFSAllocation			=> 12,
	equipmentMngt			=> 13,
	infoRetrieval			=> 14,
	interVlrInfoRetrieval		=> 15,
	subscriberDataMngt		=> 16,
	tracing				=> 17,
	networkFunctionalSs		=> 18,
	networkUnstructuredSs		=> 19,
	shortMsgGateway			=> 20,
	shortMsgMO_Relay		=> 21,
	subscriberDataModificationNotification		=> 22,
	shortMsgAlert			=> 23,
	mwdMngt				=> 24,
	shortMsgMT_Relay		=> 25,
	imsiRetrieval			=> 26,
	msPurging			=> 27,
	subscriberInfoEnquiry		=> 28,
	anyTimeInfoEnquiry		=> 29,
	groupCallControl		=> 31,
	gprsLocationUpdate		=> 32,
	gprsLocationInfoRetrieval	=> 33,
	failureReport			=> 34,
	gprsNotify			=> 35,
	ss_InvocationNotification	=> 36,
	locationSvcGateway		=> 37,
	locationSvcEnquiry		=> 38,
	authenticationFailureReport	=> 39,
	secureTransportHandling		=> 40,
	shortMsgMT_Relay_VGCS_		=> 41,
	mm_EventReporting		=> 42,
	anyTimeInfoHandling		=> 43,
	resourceManagement		=> 44,
	groupCallInfoRetrieval		=> 45,
);

my %GSMMAP_OP = reverse (
	updateLocationArea		=> 1,
	updateLocation			=> 2,
	cancelLocation			=> 3,
	provideRoamingNumber		=> 4,
	detachIMSI			=> 5,
	noteSubscriberDataModified	=> 5,
	attachIMSI			=> 6,
	resumeCallHandling		=> 6,
	insertSubscriberData		=> 7,
	deleteSubscriberData		=> 8,
	SendParameters			=> 9,
	registerSS			=> 10,
	eraseSS				=> 11,
	activatess			=> 12,
	deactivateSS			=> 13,
	interrogateSS			=> 14,
	authenticationFailureReport	=> 15,
	invokeSS			=> 15,
	forwardSSNotification		=> 16,
	registerPassword		=> 17,
	getPassword			=> 18,
	ProcessUnstructuredSS_Data	=> 19,
	SendInfoForIncomingCall		=> 20,
	SendInfoForOutgoingCall		=> 21,
	sendRoutingInfo			=> 22,
	CompleteCall			=> 23,
	updateGprsLocation		=> 23,
	ConnectToFollowingAddress	=> 24,
	sendRoutingInfoForGprs		=> 24,
	failureReport			=> 25,
	processCallWaiting		=> 25,
	noteMsPresentForGprs		=> 26,
	Page				=> 26,
	searchForMobileSubscriber	=> 27,
	PerformHandover			=> 28,
	sendEndSignal			=> 29,
	PerformSubsequentHandover	=> 30,
	allocateForHandoverNumber	=> 31,
	provideSIWFSNumber		=> 31,
	sendHandOverReport		=> 32,
	SIWFSSignallingModify		=> 32,
	processAccessSignalling		=> 33,
	forwardAccessSignalling		=> 34,
	NoteInternalHandover		=> 35,
	RegisterChargingInformation	=> 36,
	reset				=> 37,
	forwardCheckSs_Indication	=> 38,
	Authenticate			=> 39,
	prepareGroupCall		=> 39,
	provideIMSI			=> 40,
	sendGroupCallEndSignal		=> 40,
	forwardNewTMSI			=> 41,
	processGroupCallSignalling	=> 41,
	forwardGroupCallSignalling	=> 42,
	setCipheringMode		=> 42,
	checkIMEI			=> 43,
	mt_forwardSM			=> 44,
	sendRoutingInfoForSM		=> 45,
	mo_forwardSM			=> 46,
	reportSmDeliveryStatus		=> 47,
	SetMessageWaitingData		=> 47,
	NoteMSPresent			=> 48,
	AlertServiceCenterWithoutResult	=> 49,
	activateTraceMode		=> 50,
	deactivateTraceMode		=> 51,
	TraceSubscriberActivity		=> 52,
	ProcessAccessRequest		=> 53,
	BeginSubscriberActivity		=> 54,
	sendIdentification		=> 55,
	sendAuthenticationInfo		=> 56,
	restoreData			=> 57,
	sendIMSI			=> 58,
	processUnstructuredSS_Request	=> 59,
	unstructuredSS_Request		=> 60,
	unstructuredSS_Notify		=> 61,
	anyTimeSubscriptionInterrogation=> 62,
	informServiceCentre		=> 63,
	alertServiceCentre		=> 64,
	anyTimeModification		=> 65,
	readyForSM			=> 66,
	purgeMS				=> 67,
	prepareHandover			=> 68,
	prepareSubsequentHandover	=> 69,
	provideSubscriberInfo		=> 70,
	anyTimeInterrogation		=> 71,
	ss_Invocation_Notification	=> 72,
	setReportingState		=> 73,
	statusReport			=> 74,
	remoteUserFree			=> 75,
	registerCC_Entry		=> 76,
	eraseCC_Entry			=> 77,
	secureTransportClass1		=> 78,
	secureTransportClass2		=> 79,
	secureTransportClass3		=> 80,
	secureTransportClass4		=> 81,
	provideSubscriberLocation	=> 83,
	sendRoutingInfoForLCS		=> 85,
	subscriberLocationReport	=> 86,
	istAlert			=> 87,
	istCommand			=> 88,
	NoteMM_Event			=> 89,
);

my %CAP_OP = reverse (
	InitialDP			=> 0,
	AssistRequestInstructions	=> 16,
	EstablishTemporaryConnection	=> 17,
	DisconnectForwardConnection	=> 18,
	ConnectToResource		=> 19,
	Connect				=> 20,
	ReleaseCall			=> 22,
	RequestReportBCSMEvent		=> 23,
	EventReportBCSM			=> 24,
	CollectInformation		=> 27,
	Continue			=> 31,
	InitiateCallAttempt		=> 32,
	ResetTimer			=> 33,
	FurnishChargingInformation	=> 34,
	ApplyCharging			=> 35,
	ApplyChargingReport		=> 36,
	CallGap				=> 41,
	CallInformationReport		=> 44,
	CallInformationRequest		=> 45,
	SendChargingInformation		=> 46,
	PlayAnnouncement		=> 47,
	PromptAndCollectUserInformation	=> 48,
	SpecializedResourceReport	=> 49,
	Cancel				=> 53,
	ActivityTest			=> 55,
	InitialDPSMS			=> 60,
	FurnishChargingInformationSMS	=> 61,
	ConnectSMS			=> 62,
	RequestReportSMSEvent		=> 63,
	EventReportSMS			=> 64,
	ContinueSMS			=> 65,
	ReleaseSMS			=> 66,
	ResetTimerSMS			=> 67,
	ActivityTestGPRS		=> 70,
	ApplyChargingGPRS		=> 71,
	ApplyChargingReportGPRS		=> 72,
	CancelGPRS			=> 73,
	ConnectGPRS			=> 74,
	ContinueGPRS			=> 75,
	EntityReleasedGPRS		=> 76,
	FurnishChargingInformationGPRS	=> 77,
	InitialDPGPRS			=> 78,
	ReleaseGPRS			=> 79,
	EventReportGPRS			=> 80,
	RequestReportGPRSEvent		=> 81,
	ResetTimerGPRS			=> 82,
	SendChargingInformationGPRS	=> 83,
	DFCWithArgument			=> 86,
	ContinueWithArgument		=> 88,
	DisconnectLeg			=> 90,
	MoveLeg				=> 93,
	SplitLeg			=> 95,
	EntityReleased			=> 96,
	PlayTone			=> 97,
);

my $log = $0;
$log =~ s/(\.pl)?\z/.log/;
open STDERR, '>', $log or die "open $log: $!";
select STDERR; $|++; select STDOUT; $|++;

sub error($$) {
	my ($pkt, $msg) = @_;

	use Data::Dumper;
	print STDERR "pkt = ", Dumper ($pkt) if $pkt;
	print STDERR ">>> ", (caller 1)[3], ": $msg\n";
	print "!!! ", (caller 1)[3], ": $msg\n";
	die "normal error";
}

sub decode_tlv_nn {
	my ($data) = @_;

	my %hash;
	while (length $data) {
		my ($type, $len) = unpack 'nn', $data;
		$len -= 4;
		($hash{$type}, $data) = unpack "x4 a$len x![N] a*", $data;
	}
	return \%hash;
}

sub hlookup {
	my ($href, $key) = @_;

	exists $href->{$key} ? $href->{$key} : "$key?";
}

#
# sctp
#

sub sctp_connect {
	$sctp_fh = IO::Socket::INET->new (
		Proto		=> 132,
		Type		=> SOCK_STREAM,
		LocalAddr	=> $src_host,
		LocalPort	=> $src_port,
		PeerAddr	=> $dst_host,
		PeerPort	=> $dst_port,
	) or error undef, $!;
	binmode $sctp_fh or die;

	print "*** connected to $dst_host:$dst_port\n";
}

sub sendmsg_sol {
	my ($fh, $msg, $flag) = @_;

	# sys/syscall.h SYS_sendmsg
	return syscall (241, $fh, $msg, $flag);
}

sub sendmsg_lin64 {
	my ($fh, $msg, $flag) = @_;

	# SYS_sendmsg
	return syscall (46, $fh, $msg, $flag);
}

sub sendmsg_lin32 {
	my ($fh, $msg, $flag) = @_;

	# SYS_socketcall
	return syscall (102, 16, pack "iPi", $fh, $msg, $flag);
}

*sendmsg =
	$^O eq 'solaris' ? \&sendmsg_sol :
	$^O eq 'linux' ?
		$Config{archname} =~ /x86_64/ ?
			\&sendmsg_lin64 :
			\&sendmsg_lin32 :
	die "unsupported OS $^O";

sub sctp_send {
	my ($pid, $si, $msg) = @_;

	# based on opensolaris lib/libsctp/common/sctp.c sctp_send_common
	#
	# checked with
	#     http://lksctp.git.sourceforge.net/git/gitweb.cgi?p=
	#        lksctp/lksctp;a=blob;f=src/lib/sendmsg.c;hb=HEAD

	# netinet/sctp.h struct sctp_sndrcvinfo
	my $sinfo = pack 'S S S x![L] L L L L L i',
		$si,		# uint16_t	sinfo_stream;
		0,		# uint16_t	sinfo_ssn;
		0,		# uint16_t	sinfo_flags;
		$pid,		# uint32_t	sinfo_ppid;
		0,		# uint32_t	sinfo_context;
		0,		# uint32_t	sinfo_timetolive;
		0,		# uint32_t	sinfo_tsn;
		0, 		# uint32_t	sinfo_cumtsn;
		0,		# sctp_assoc_t	sinfo_assoc_id;
	;

	my $SCTP_SNDRCV = $^O eq 'solaris' ? 0x100 : 1;

	# sys/socket.h struct cmsghdr
	my $cmsg = pack 'I i i',
		0,		# socklen_t	cmsg_len;
		132,		# int		cmsg_level; /* IPPROTO_SCTP */
		$SCTP_SNDRCV,	# int		cmsg_type; /* SCTP_SNDRCV */
	;

	$cmsg |= pack 'I', length ($cmsg . $sinfo);

	my $ctl = $cmsg . $sinfo;

	# sys/uio.h struct iovec
	my $iov = pack 'P i',
		$msg,		# void		*iov_base;
		length $msg,	# size_t	iov_len;
	;

	# sys/socket.h struct msghdr
	my $hdr = pack "P I P i P I i",
		undef,		# void		*msg_name;
		0,		# socklen_t	msg_namelen;
		$iov,		# struct iovec	*msg_iov;
		1,		# int		msg_iovlen;
		$ctl,		# void		*msg_control;
		length $ctl,	# socklen_t	msg_controllen;
		0,		# int		msg_flags;
	;

	sendmsg (fileno $sctp_fh, $hdr, 0) == length $msg
		or error undef, $!;
}

sub sctp_recv {
	$sctp_fh->recv (my $data, 10000) or die $!;
	m3ua_parse ({}, $data);
}

#
# m3ua
#

sub m3ua_send {
	my ($class, $type, @tv) = @_;

	my $tlv = '';
	while (@tv) {
		my ($tag, $val) = splice @tv, 0, 2;		
		$tlv .= pack 'nna*', $tag, 4 + length $val, $val;
	}
	sctp_send ($SCTP_PAYLOAD{M3UA}, $class == 1, pack 'CCCCNa*',
		1, 0, $class, $type, 8 + length $tlv, $tlv);
}

sub m3ua_send_data_response {
	my ($pkt, $data) = @_;

	my %tv = %{ $pkt->{m3ua}{param} };

	$tv{0x0210} = pack 'NNCCCCa*',
		@{ $pkt->{m3ua} }{qw/ dpc opc si ni mp sls /}, $data;
			# replace opc<->dpc, data

	m3ua_send (1, 1, %tv);
}

sub m3ua_parse {
	my ($pkt, $data) = @_;

	$pkt->{m3ua} = \my %m3ua;

	@m3ua{qw/ ver class type len tlvs /} = unpack 'CxCCNa*', $data;

	error $pkt, "ver $m3ua{ver}!=1"
		if $m3ua{ver} != 1;
	$m3ua{param} = decode_tlv_nn ($m3ua{tlvs});

	if ($m3ua{class} == 1 && $m3ua{type} == 1) { # DATA

		error $pkt, 'no Protocol Data in DATA'
			if !exists $m3ua{param}{0x0210};

		@m3ua{qw/ opc dpc si ni mp sls userdata /} =
			unpack 'NNCCCCa*', $m3ua{param}{0x0210};

		if ($m3ua{si} == 3) {
			sccp_parse ($pkt, $m3ua{userdata});
		} else {
			error $pkt, "si $m3ua{si}";
		}
		
	} elsif ($m3ua{class} == 0 && $m3ua{type} == 1) { # NTFY

		if ($m3ua_rc) {
			print "*** got m3ua NTFY again\n";
			return;
		}

		$m3ua_rc = unpack 'N', $m3ua{param}{6};

		print "*** got m3ua NTFY(routing context=$m3ua_rc), sending m3ua ASPAC\n";

		m3ua_send (4, 1,		# ASPAC, 
			0xb => pack ('N', 1),	# Traffic Mode Type = Override
		);

	} elsif ($m3ua{class} == 2) {
		my ($mask, $apc) = exists $m3ua{param}{0x0012} ?
			unpack 'CXN', $m3ua{param}{0x0012} :
			('?', '?');
		print "*** got m3ua management " .
			hlookup ({reverse %M3UA_SSNM}, $m3ua{type}) .
			" apc=$apc/$mask\n";
	} elsif ($m3ua{class} == 3 && $m3ua{type} == 4) { # ASPUP_ACK
		print "*** got m3ua ASPUP_ACK\n";
	} elsif ($m3ua{class} == 4 && $m3ua{type} == 3) { # ASPAC_ACK
		print "*** got m3ua ASPAC_ACK\n";

		fsm_hack ($pkt) if $fsm_hack;
		idp_hack ($pkt) if $idp_hack;
	} else {
		error $pkt, "class $m3ua{class} type $m3ua{type}";
	}
}

#
# sccp
#

sub sccp_send_udt_response {
	my ($pkt, $data) = @_;

	my $cgpa = $pkt->{sccp}{cdpabin};
	my $cdpa = $pkt->{sccp}{cgpabin};

	my $sccp = pack 'CC CCC Ca* Ca* Ca*', $SCCP_TYPE{UDT}, 0x80,
		3,
		3 + length $cdpa,
		3 + length ($cdpa) + length $cgpa,
		length $cdpa, $cdpa,
		length $cgpa, $cgpa,
		length $data, $data;
	m3ua_send_data_response ($pkt, $sccp);
}

sub sccp_parse {
	my ($pkt, $data) = @_;

	$pkt->{sccp} = \my %sccp;

	$sccp{type} = unpack 'C', $data;

	if ($sccp{type} == $SCCP_TYPE{UDTS}) {
		$sccp{cause} = unpack 'xC', $data;
		if ($sccp{cause} == 1) {
			error $pkt, "UTDS cause: no gtt";
		} else {
			error $pkt, "UTDS cause $sccp{cause}";
		}
		return;
	}

	error $pkt, "type " . hlookup ({reverse %SCCP_TYPE}, $sccp{type})
		if $sccp{type} != $SCCP_TYPE{UDT};
	
	@sccp{qw/ type class ptr1 ptr2 ptr3 cdpabin cgpabin data /} =
		unpack 'CCCCCC/aC/aC/a', $data;

	#error $pkt, "class/message handling $sccp{class}"
	#	if $sccp{class} != 0x80 && $sccp{class} != 0x00;

	for (qw/ cdpa cgpa /) {
		my $a = $sccp{"${_}bin"};
		$sccp{$_} = \my %a;

		(my ($ai), $a) = unpack 'Ca*', $a;

		$a{ri} = $ai & 64;
		$a{gti} = $ai >> 2 & 7;

		($a{pc}, $a) = unpack 'va*', $a
			if $ai & 1;
		($a{ssn}, $a) = unpack 'Ca*', $a
			if $ai & 2;

		if ($a{gti} == 0) {
			# nothing
		} elsif ($a{gti} == 2) {
			($a{tt}, $a) = unpack 'Ca*', $a;
		} elsif ($a{gti} == 4) {
			(@a{qw/ tt planenc nai /}, $a) = unpack 'CCCa*', $a;
		} else {
			error $pkt, "gti $a{gti}";
		}

		$a{address} = unpack 'h*', $a;
		chop $a{address}
			if ($a{planenc} || 0) & 1;
	}

	tcap_parse ($pkt, $sccp{data});
}

#
# asn.1
#

sub asn1_decode_pdu {
	my ($dataref, $tab) = @_;

	(my ($type), $$dataref) = unpack 'Ca*', $$dataref;

	my $txt = qw/ universal application context private /[$type >> 6];

	my $tag = $type & 0x1f;
	($tag, $$dataref) = unpack 'wa*', $$dataref
		if $tag == 0x1f;

	(my ($len), $$dataref) = unpack 'Ca*', $$dataref;
	if ($len & 0x80) {
		$len &= 0x7f;
		die "len is more then 4 bytes"
			if $len > 4;
		($len, $$dataref) = unpack "a$len a*", $$dataref;
		$len = unpack 'N', "\0" x (4 - length $len) . $len;
	}
	die "message too short"
		if length $$dataref < $len;

	(my ($val), $$dataref) = unpack "a$len a*", $$dataref;
	
	if ($type & 0x20) {
		my $t = '';
		my $ta = "$tab   ";
		$t .= $ta . asn1_decode_pdu (\$val, $ta) . "\n"
			while length $val;
		$val = "<\n$t$tab>";
	} else {
		$val = '= "' . unpack ('H*', $val) . '"';
	}

	return "${txt}_$tag $val";
}

sub asn1_decode {
	my ($data) = @_;

	my $ret = asn1_decode_pdu (\$data, '');
	warn "garbage at the end"
		if length $data;
	return $ret;
}

sub asn1_encode_pdu {
	my ($txt) = @_;

	$$txt =~ s/^\s*([uacp])[a-z]*_(\d+)\s*//i
		or die "bad syntax at:\n$$txt";
	my ($type, $tag) = ($1, $2);

	$type = { u => 0, a => 0x40, c => 0x80, p => 0xc0 }->{lc $type};
	$type |= $tag < 0x1f ? $tag : 0x1f;
	$type = pack 'C', $type;
	$type .= pack 'w', $tag
		if $tag >= 0x1f;

	my $val = '';

	if ($$txt =~ s/^=//) {
		$$txt =~ s/^\s*"\s*([0-9a-f]*)\s*"\s*//i
			or die "bad syntax of = at:\n$$txt";
		$val = pack 'H*', $1;
	} elsif ($$txt =~ s/^<//) {
		$type |= pack 'C', 0x20;
		$val .= asn1_encode_pdu ($txt)
			while $$txt =~ /^\s*[a-z]/i;
		$$txt =~ s/^\s*>\s*//
			or die "no closing > at:\n$$txt";
	} else {
		die "bad syntax at:\n$$txt";
	}

	my $len = length $val;
	if ($len < 0x80) {
		$len = pack 'C', $len;
	} else {
		$len = pack 'N', $len;
		$len =~ s/^\0*//;
		$len = pack 'Ca*', 0x80 | length $len, $len;
	}

	return "$type$len$val";
}

sub asn1_encode {
	my ($txt) = @_;

	my $pdu = asn1_encode_pdu (\$txt);
	$txt =~ /^\s*\z/
		or die "garbade at the end:\n$txt";
	return $pdu;
}

my $d_re = qr/[0-9a-f]*/;
my $asn1_re;
{
	use re 'eval';
	$asn1_re = qr/ \w+\d+ = "$d_re" | \w+\d+ < (?:(??{ $asn1_re }))* > /x;
}

#
# tcap
#

sub tcap_fix {
	my ($pkt) = @_;

	$pkt->{tcap}{ac} = sprintf '0400000100%02x0%1d',
		{reverse %GSMMAP_APP}->{ $pkt->{tcap}{application} },
		$pkt->{tcap}{ver};
	$pkt->{tcap}{opCode} = sprintf '%02x',
		{reverse %GSMMAP_OP}->{ $pkt->{tcap}{operation} };
}

sub tcap_send_begin_ {
	my ($pkt, $asn) = @_;

	tcap_fix ($pkt);

	my $out = qq!

application_2 <					# begin
   application_8 = "$pkt->{tcap}{otid}"		# otid
   application_11 <				# dialoguePortion
      universal_8 <				# ExternalPDU
         universal_6 = "$pkt->{tcap}{oid}"	# oid
         context_0 <				# dialog
            application_0 <			# dialogueRequest
               context_0 = "0780"		# protocol-versionrq
               context_1 <			# application-context-name
                  universal_6 = "$pkt->{tcap}{ac}"
               >
            >
         >
      >
   >
   application_12 <				# components
      context_1 <				# invoke
         universal_2 = "$pkt->{tcap}{invokeId}"	# invokeID
         universal_2 = "$pkt->{tcap}{opCode}"	# opCode
         $asn
      >
   >
>
	!;
	$out =~ s/#.*//g;
	sccp_send_udt_response ($pkt, asn1_encode ($out));
}


sub tcap_send_end_response {
	my ($pkt, $asn) = @_;

	tcap_fix ($pkt);

	my $out = qq!

application_4 <					# end
   application_9 = "$pkt->{tcap}{otid}"		# dtid
   application_11 <				# dialoguePortion
      universal_8 <
         universal_6 = "$pkt->{tcap}{oid}"	# oid
         context_0 <				# dialog
            application_1 <			# dialogueResponse
               context_0 = "0780"		# protocol-versionre
               context_1 <			# application-context-name
                  universal_6 = "$pkt->{tcap}{ac}"
               >
               context_2 <			# result
                  universal_2 = "00"		# accepted
               >
               context_3 <			# result-source-diagnostic
                  context_1 <			# dialog-service-user
                     universal_2 = "00"		# null
                  >
               >
            >
         >
      >
   >
   application_12 <				# components
      $asn
   >
>
	!;
	$out =~ s/#.*//g;
	sccp_send_udt_response ($pkt, asn1_encode ($out));
}

sub tcap_send_end_returnResultLast {
	my ($pkt, $asn) = @_;

	tcap_send_end_response ($pkt, qq!
	    context_2 <					# returnResultLast
		universal_2 = "$pkt->{tcap}{invokeId}"	# invokeId
@{[ $asn && qq%
		universal_16 <				# returnretres
		    universal_2 = "$pkt->{tcap}{opCode}"# opCode
		    $asn
		>
%]}
	    >
	!);
}

sub tcap_send_end_returnError {
	my ($pkt, $error) = @_;

	tcap_send_end_response ($pkt, qq!
	    context_3 <					# returnError
		universal_2 = "$pkt->{tcap}{invokeId}"	# invokeId
		universal_2 = "$error"			# localValue
	    >
	!);
}

sub tcap_parse {
	my ($pkt, $data) = @_;

	$pkt->{tcap} = \my %tcap;

	my $in = asn1_decode ($data);
	$tcap{in} = $in;
	$in =~ s/\s+//g;

	(my $type) = $in =~ /^application_(\d+)</
		or error $pkt, 'no match';

	exists $TCAP_TYPE{$type}
		or error $pkt, "type $type";
	$tcap{type} = $TCAP_TYPE{$type};
	$type = "tcap_parse_$TCAP_TYPE{$type}";

	no strict 'refs';
	exists &$type
		or error $pkt, "unimplemented $type";
	$type->($pkt, $in);
}

sub tcap_parse_begin {
	my ($pkt, $in) = @_;

	my $tcap = $pkt->{tcap};

	@{ $tcap }{qw/ otid oid ac component invokeId opCode gsmmap /} = $in =~ qr!^

application_2 <					# begin
   application_8 = "($d_re)"			# otid			1
   application_11 <				# dialoguePortion
      universal_8 <				# ExternalPDU
         universal_6 = "($d_re)"		# oid			2
         context_0 <				# dialog
            application_0 <			# dialogueRequest
               context_0 = "0780"		# protocol-versionrq
               context_1 <			# application-context-name
                  universal_6 = "($d_re)"	#			3
               >
            >
         >
      >
   >
   application_12 <				# components
      context_(1) <				# invoke
         universal_2 = "($d_re)"		# invokeID		4
         universal_2 = "($d_re)"		# opCode		5
         ($asn1_re*)				# GSM_MAP		6
      >
   >
>
	\z!x
		or error $pkt, 'no match';

	tcap_parsecontinue ($pkt);
}

sub tcap_parse_end {
	my ($pkt, $in) = @_;

	my $tcap = $pkt->{tcap};

	@{ $tcap }{qw/ dtid oid ac drest component invokeId opCode op /} = $in =~ qr!^

application_4 <					# end
   application_9 = "($d_re)"			# dtid			1
   application_11 <				# dialoguePortion
      universal_8 <
         universal_6 = "($d_re)"		# oid			2
         context_0 <				# dialog
            application_1 <			# dialogueResponse
               context_0 = "0780"		# protocol-versionre
               context_1 <			# application-context-name
                  universal_6 = "($d_re)"	#			3
               >
               ($asn1_re*)			# ...rest		4
            >
         >
      >
   >
   application_12 <				# components
      context_(7|2) <				# returnResult(Last)    5
         universal_2 = "($d_re)"		# invokeID		6
         universal_16 <				# returnretres
            universal_2 = "($d_re)"		# opCode		7
            ($asn1_re*)				# ...			8
         >
      >
   >
>
	\z!x
		or error $pkt, 'no match';

	tcap_parsecontinue ($pkt);
}

sub tcap_parsecontinue {
	my ($pkt) = @_;

	my $tcap = $pkt->{tcap};

	(my ($ac), $tcap->{ver}) = $tcap->{ac} =~ /0400000100(\w\w)0(\d)/
		or error $pkt, 'ac';
	$ac = hex $ac;
	exists $GSMMAP_APP{$ac}
		or error $pkt, "unknown application $ac";
	$tcap->{application} = $ac = $GSMMAP_APP{$ac};

	my $c = $tcap->{component};
	exists $TCAP_COMPONENT{$c}
		or error $pkt, "unknown component type $c";
	$c = $TCAP_COMPONENT{$c};

	error $pkt, 'opcode len is more then byte'
		if length $tcap->{opCode} > 2;
	my $op = hex $tcap->{opCode};
	exists $GSMMAP_OP{$op}
		or error $pkt, "unknown operator $op";

	$tcap->{operation} = $op = $GSMMAP_OP{$op};
	print "*** got GSMMAP application $ac ver $tcap->{ver} component $c op $op\n";
	$op = "gsmmap_${c}_$op";

	no strict 'refs';
	if (exists &$op) {
		$op->($pkt, $tcap->{gsmmap});
	} else {
		error $pkt, "operation $op is not implemented";
	}
}

#
# gsmmap
#

sub gsmmap_invoke_sendRoutingInfoForSM {
	my ($pkt, $asn) = @_;

	my ($msisdn) = $asn =~ qr!^
         universal_16 <				# RoutingInfoForSMArg
            context_0 = "($d_re)"		# msisdn	1
            context_1 = "($d_re)"		# sm-RP-PRI
            context_2 = "($d_re)"		# serviceCentreAddress
            $asn1_re*
         >
	\z!x
		or error $pkt, 'no match';

	print "*** got SRIforSM msisdn=$msisdn, sending imsi $srism_imsi locationInfoWithLMSI $srism_location\n";
	
	tcap_send_end_returnResultLast ($pkt, qq!
            universal_16 <			# RoutingInfoForSM-Res
               universal_4 = "$srism_imsi"	# imsi
               context_0 <			# locationInfoWithLMSI
                  context_1 = "$srism_location"	# networkNode-Number
               >
            >
	!);
}

sub gsmmap_invoke_sendRoutingInfo {
	my ($pkt, $asn) = @_;

	my ($msisdn) = $asn =~ qr!^
         universal_16 <				# SendRoutingInfoArg
	    context_0 = "($d_re)"		# msisdn	1
#	    context_3 = "($d_re)"		# interrogationType
#	    context_6 = "($d_re)"		# gmsc-OrGsmSCF-Address
            $asn1_re*
         >
	\z!x
		or error $pkt, 'no match';

	if ($sri_error) {
		print "*** got SRI msisdn=$msisdn, sending error $sri_error\n";
		tcap_send_end_returnError ($pkt, $sri_error);
		return;
	}

	print "*** got SRI msisdn=$msisdn, sending imsi=$sri_imsi roamNum=$sri_msrn\n";

	tcap_send_end_returnResultLast ($pkt, qq!
	    context_3 <				# SendRoutingInfoRes
		context_9 = "$sri_imsi"		# imsi
		universal_4 = "$sri_msrn"	# roamingNumber
#		universal_16 <			# forwardingData
#		    context_5 = "917325791110"	# forwardedToNumber
#		    context_6 = "00"		# forwardingOptions
#		>
#		context_1 <			# ss-List
#		    universal_4 = "f4"		# plmn-specificSS-4
#		>
#		context_5 <			# basicService
#		    context_3 = "11"		# ext-Teleservice
#		>
#		context_12 = "$msisdn"		# msisdn
	    >
	!);
}

sub gsmmap_invoke_anyTimeInterrogation {
	my ($pkt, $asn) = @_;

	my ($msisdn, $scf) = $asn =~ qr!^
           universal_16 <			# AnyTimeInterrogationArg
              context_0 <			# subscriberIdentity
	         context_1 = "($d_re)"		# msisdn
	      >
    (?:       context_1 <			# requestedInfo
            (?:  context_0 = ""			# locationInformation
	)?  (?:  context_1 = ""			# subscriberState
	)?    >
  )?	      context_3 = "($d_re)"		# gsmSCF-Address
	      $asn1_re*
	   >
	\z!x
		or error $pkt, 'no match';

	print "*** got ATI msisdn=$msisdn scf=$scf, sending something\n";

	if ($ati_error) {
		tcap_send_end_returnError ($pkt, $ati_error)
			if $ati_error ne '-';
		return;
	}

	tcap_send_end_returnResultLast ($pkt, qq!
      universal_16 <
         universal_16 <				# AnyTimeInterrogationRes
            context_0 <				# locationInformation
               universal_2 = "02"		# ageOfLocationInformation
               context_0 = "1080000000000000"	# geographicalInformation
               context_1 = "919721982511F1"	# vlr-number
               context_2 = "8497973112090101"	# locationNumber
               context_3 <			# cellGlobalIdOrServiceAreaIdOrLAI
                  context_0 = "52f01013890001"	# cellGlobalIdOrServiceAreaIdFixedLength
               >
            >
            context_1 <				# subscriberState
               context_0 = ""			# assumedIdle
            >
         >
      >
	!);
}


# XXX untested
sub gsmmap_invoke_insertSubscriberData {
	my ($pkt, $asn) = @_;

	my ($msisdn) = $asn =~ qr!^
         universal_16 <				# InsertSubscriberDataArg
            context_1 = "($d_re)"		# msisdn
            context_2 = "($d_re)"		# category
            context_3 = "($d_re)"		# subscriberStatus
            $asn1_re*
         >
	\z!x
		or error $pkt, 'no match';

	print "*** got ISD msisdn=$msisdn, sending ok\n";

	tcap_send_end_returnResultLast ($pkt, qq!
            universal_16 <			# InsertSubscriberDataRes
               context_3 <			# ss-List
                  universal_4 = "b1"		# universal - allow location by any LCS client
               >
            >
	!);
}

# XXX untested
sub gsmmap_invoke_sendAuthenticationInfo {
	my ($pkt, $asn) = @_;

	my ($imsi, $num) = $asn =~ qr!^
         universal_16 <				# SendAuthenticationInfoArgV2
            context_0 = "($d_re)"		# imsi
            universal_2 = "($d_re)"		# numberOfRequestedVectors
            $asn1_re*
         >
	\z!x
		or error $pkt, 'no match';

	print "*** got SAI imsi=$imsi num=$num, sending ???\n";

	tcap_send_end_returnResultLast ($pkt, qq!
            universal_16 <			# SendAuthenticationInfoRes
               universal_16 <
                  universal_4 = "48fc9dc80a29b111a15da7214522e21f"	# rand
                  universal_4 = "097ee28c"				# sres
                  universal_4 = "8e479d05ecdf6000"			# kc
               >
               universal_16 <
                  universal_4 = "7ba45e0a3fcd6629290d8e54bc093763"
                  universal_4 = "e014cf80"
                  universal_4 = "e9c310bbd7e26800"
               >
               universal_16 <
                  universal_4 = "5cc19e048527869e0ca2fd355d67adf9"
                  universal_4 = "dffb0498"
                  universal_4 = "6925f2e2c2d3c800"
               >
               universal_16 <
                  universal_4 = "7ff00f0dc0db90ca04aad58bdb65649f"
                  universal_4 = "d2eca75d"
                  universal_4 = "8f977592bb126000"
               >
            >
	!);
}

sub gsmmap_invoke_mt_forwardSM {
	my ($pkt, $asn) = @_;

	my ($imsi, $sca, $ui) = $asn =~ qr!^
         universal_16 <
            context_0 = "($d_re)"	# sm-RP-DA: imsi	1
            context_4 = "($d_re)"	# sm-RP-OA: serviceCentreAddressOA 2
            universal_4 = "($d_re)"	# sm-RP-UI		3
         >
	!x
		or error $pkt, 'no match';

	use Data::Dumper;
	print Dumper ($pkt);

	print "*** got mt-FSM imsi=$imsi serviceCentreAddressOA=$sca\n";
	sms_parse ($pkt, pack 'H*', $ui);

	print "*** sending ok\n";
	tcap_send_end_returnResultLast ($pkt, '');
}

#
# sms
#

sub sms_parse {
	my ($pkt, $pdu) = @_;

	my ($type) = unpack 'C', $pdu;

	if (($type & 3) == 0) {
		my ($addrlen) = unpack 'xC', $pdu;
		my ($np, $addr, $pid, $enc, $time, $data) =
			unpack "xxH2h${addrlen}CCh14C/A", $pdu;

		print "*** got SMS-SUBMIT addr=$addr np=$np yymmddHHMMSSzz=$time\n";

		my $text = pack 'H*', $data;
		if ($enc == 0) {
			$data = unpack 'b*', $data;
			$data =~ s/(.{7})/${1}0/g;
			$text = decode ('gsm0338', pack 'b*', $data);
		} elsif ($enc == 8) {
			$text = encode ('cp866', decode ('UCS-2BE', $data));
		} else {
			print "*** sms encoding $enc unknown\n";
		}
		print "*** sms text '$text'\n";
	} else {
		error $pkt, "type $type is unknown";
	}
}

if (0) {
	use Data::Dumper;
	sms_parse (undef, pack 'H*',
		'240b919720130704f600007060416150636104d4f29c0e');
	exit;
}

#
# fsm hack
#
sub fsm_hack {
	my ($pkt) = @_;

	$pkt->{m3ua} = {
		%{ $pkt->{m3ua} },
		dpc	=> 4114,
		opc	=> 4114,
		si	=> 3,
		ni	=> 0,
		mp	=> 0,
		sls	=> 8,
	};
	$pkt->{sccp} = {
		cgpabin => pack ('H*', '120c0012042926000000'),
		cdpabin => pack ('H*', '12060012042966111111'),
	};

	my $out = qq!
application_2 <
   application_8 = "00000007"
   application_11 <
      universal_8 <
         universal_6 = "00118605010101"
         context_0 <
            application_0 <
               context_0 = "0780"
               context_1 <
                  universal_6 = "04000001001903"
               >
            >
         >
      >
   >
   application_12 <
      context_1 <
         universal_2 = "01"
         universal_2 = "2e"
         universal_16 <
            context_0 = "52077224007353f2"	# sm-RP-DA
            context_4 = "912926000000"		# sm-RP-OA
						# sm-RP-UI
            universal_4 = "040d91538316325476f80000203092706423000af3f61c647ecb41ed32"
            universal_4 = "52002188220812f4"	# imsi
         >
      >
   >
>
!;
	$out =~ s/#.*//g;
	print "*** sending some mo-fsm\n";
	sccp_send_udt_response ($pkt, asn1_encode ($out));
}

#
# idp hack
#
sub idp_hack {
	my ($pkt) = @_;

	$pkt->{m3ua} = {
		%{ $pkt->{m3ua} },
		dpc	=> 4114,
		opc	=> 4114,
		si	=> 3,
		ni	=> 0,
		mp	=> 0,
		sls	=> 8,
	};
	$pkt->{sccp} = {
		cgpabin => pack ('H*', '120c0012042726000000'),
		cdpabin => pack ('H*', '12060012042766111111'),
	};

	my $out = qq!
application_2 <
   application_8 = "4b3160fc"
   application_11 <
      universal_8 <
         universal_6 = "00118605010101"
         context_0 <
            application_0 <
               context_1 <
                  universal_6 = "04000001003201"
               >
            >
         >
      >
   >
   application_12 <
      context_1 <
         universal_2 = "01"
         universal_2 = "00"
         universal_16 <
            context_0 = "1e"
            context_3 = "03131940706400"
            context_5 = "0a"
            context_10 = "8497976198051101"
            context_23 = "9181"
            context_27 <
               context_0 = "8090a3"
            >
            context_28 = "02"
            context_50 = "52006171003225f6"
            context_52 <
               universal_2 = "00"
               context_1 = "919761980511f1"
               context_3 <
                  context_0 = "52f01006430856"
               >
            >
            context_53 <
               context_3 = "11"
            >
            context_54 = "7e8edf7a42"
            context_55 = "919761980511f1"
            context_56 = "819861017083f7"
            context_57 = "0201109231218021"
         >
      >
   >
>
!;
	$out =~ s/#.*//g;
	print "*** sending some idp\n";
	sccp_send_udt_response ($pkt, asn1_encode ($out));
}


sctp_connect ();
m3ua_send (3, 1); # ASPSM/ASPUP
sctp_recv () while 1;


