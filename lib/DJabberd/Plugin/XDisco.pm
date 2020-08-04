package DJabberd::Plugin::XDisco;
use strict;
use base 'DJabberd::Plugin';
use warnings;
use Digest::SHA qw(sha1_base64 hmac_sha1_base64);

use constant NS_XDISCOv2 => 'urn:xmpp:extdisco:2';

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Plugin::XDisco - Implements XEP-0215 External Service Discovery protocol

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Implements XEP-0215 External Service Discovery protocol.

    <VHost mydomain.com>
	<Plugin DJabberd::Plugin::XDisco>
	    ServiceURI turn:1.2.3.4:9991?transport=udp
	    ServiceURI turn:1.2.3.4:9992?transport=tcp
	    ServiceCreds ltc:1.2.3.4?username=anon&password=123
	    ServiceURI turns:4.3.2.1:443?transport=tcp
	    ServiceCreds stc:4.3.2.1:443?hmac=sha1&psk=secret
	</Plugin>
    </VHost>


=over

=item ServiceURI

Specifies list of services in RFC 7065 format. These services will be advertised in response to extdisco query.
Plugin will skip registration (and hence disco feature injection) if there are no ServiceURIs defined.

=item ServiceCreds

Optional credentials for each advertised service. Credentials could be either Long-Term-Credentials (static
username and password) or Short-Term-Credentials calculated as described in 
L<draft-uberti-behave-turn-rest|https://tools.ietf.org/html/draft-uberti-behave-turn-rest-00>.
The format of credentials string is C<schema> : C<host>[: C<port>] ? C<params> (similar to URI specification)
where C<schema> could be C<ltc> or C<stc> for Long-Term-Credentials and Short-Term-Credentials respectively.

Valid (and required) C<params> for scheme C<ltc> are C<username> and C<password>.

Valid (and required) C<params> for scheme C<stc> are C<hmac> and C<psk> where C<hmac> specifies HMAC algorithm
used to calculate time-based password from username, and C<psk> is shared secret used by HMAC. These values
should match those set on TURN/STUN server.

Each Creds line is a suppliment for the URI[s] - that means Creds for non-existing URIs are ignored.
That also means order is important and Creds should always be defined after corresponding URI - not immediately
following but at any line after URI definition. If C<port> is not defined for credentials - it will apply to
all services on that host. Again order is important and it is possible to define wildcard credentials for a
host and then override it with more specific one.

=back

=cut

sub add_config_serviceuri {
    my $self = shift;
    my $val = shift;
    $self->{svs} = {} unless(ref($self->{svs}));
    if($val =~ /^([^:]+):([^?]+)\?(.+)$/) {
	my ($type, $hp, $params) = ($1, $2, $3);
	return $logger->debug("Ignoring paramless service $val") unless($params);
	my ($host, $port) = split(':',$hp);
	return $logger->debug("Ignoring portless service $val") unless($port);
	my %params = map{split'='}split('&', $params);
	my $svc = { host=> $host, port => $port, type => $type };
	$svc->{transport} = $params{transport} if($params{transport});
	$self->{svs}{$val} = $svc;
    }
}

sub add_config_servicecreds {
    my $self = shift;
    my $val = shift;
    if($val =~ /^([^:]+):([^?]+)\?(.+)$/) {
	my ($type, $hp, $params) = ($1, $2, $3);
	return $logger->debug("Ignoring paramless service $val") unless($params);
	my ($host, $port) = split(':',$hp);
	my %params = map{split'='}split('&', $params);
	return $logger->debug("Ignoring cred $val: type") unless($type eq 'ltc' || $type eq 'stc');
	return $logger->debug("Ignoring cred $val: params") if($type eq 'ltc' && !$params{username} && !$params{password});
	return $logger->debug("Ignoring cred $val: params") if($type eq 'stc' && !$params{hmac} && !$params{psk});
	$params{type} = $type;
	my $re = ($port ? qr/^[^:]+:$host:$port\?.+/ : qr/^[^:]+:$host(?::\d+)?\?.+/);
	for my $uri (keys(%{$self->{svs} || {}})) {
	    if($uri =~ $re) {
		$self->{svs}{$uri}{cred} = \%params;
		$logger->debug("Adding credentials $val to $uri");
	    }
	}
    }
}

sub finalize {
    my $self = shift;
    $self->{svs} ||= {};
}

=head2 register($self, $vhost)

Register the vhost with the module.

=cut

sub register {
    my ($self,$vhost) = @_;
    # Don't waste time if we have nothing to offer
    if(scalar(keys(%{$self->{svs}})) > 0) {
	my $xdisco_cb = sub {
	    my ($vh, $cb, $iq) = @_;
	    if($vhost->handles_domain($iq->to) &&
	      ( $iq->signature eq 'get-{'.NS_XDISCOv2.'}services'
	      ||$iq->signature eq 'get-{'.NS_XDISCOv2.'}credentials')) {
		$self->xdisco($iq);
		return $cb->stop_chain;
	    }
	    $cb->decline;
	};
	$self->{vhost} = $vhost;
	Scalar::Util::weaken($self->{vhost});
	$vhost->register_hook("c2s-iq",$xdisco_cb);
	$vhost->register_hook("s2s-iq",$xdisco_cb);
	# Add features
	$vhost->caps->add(DJabberd::Caps::Feature->new(NS_XDISCOv2));
	$logger->debug("Registered external discovery plugin");
    } else {
	$logger->debug("Skipping registration");
    }
}

sub vh {
    return $_[0]->{vhost};
}

sub xdisco {
    my ($self,$iq) = @_;
    my $type = $iq->first_element->attr('{}type');
    my ($for) = grep{$_->element_name eq 'service'}$iq->first_element->children_elements;
    $type = $for->attr('{}type') if($for && $for->attr('{}type'));
    my $rsp = $iq->make_response;
    my $srv = DJabberd::XMLElement->new(NS_XDISCOv2, 'services', { xmlns=>NS_XDISCOv2}, []);
    $srv->set_attr('{}type'=>$type) if($type);
    for my $svc (map{$self->{svs}{$_}}sort(keys(%{ $self->{svs} }))) {
	next if($type && $svc->{type} ne $type);
	next if($for && $svc->{host} ne $for->attr('{}host'));
	next if($for && $for->attr('{}port') && $svc->{port} != $for->attr('{}port'));
	my $s = DJabberd::XMLElement->new(undef, 'service', {
	    '{}type' => $svc->{type},
	    '{}host' => $svc->{host},
	    '{}port' => $svc->{port},
	});
	$s->set_attr('{}transport' => $svc->{transport}) if($svc->{transport});
	if(ref($svc->{cred})) {
	    my $c = $svc->{cred};
	    if($c->{type} eq 'ltc') {
		$s->set_attr('{}username'=>$c->{username});
		$s->set_attr('{}password'=>$c->{password});
	    } elsif($c->{type} eq 'stc') {
		my $user = (time+3600).':'.sha1_base64($iq->from);
		my $pass;
		if($c->{hmac} eq 'sha1') {
		    $pass = hmac_sha1_base64($user, $c->{psk});
		} else {
		    $logger->debug('Unknown digest type '.$c->{hmac});
		    next;
		}
		$s->set_attr('{}username'=>$user);
		$s->set_attr('{}password'=>$pass);
	    }
	}
	$srv->push_child($s);
    }
    $rsp->push_child($srv);
    $rsp->deliver($self->vh);
}
