#!/usr/bin/perl
use strict;
use Test::More tests => 20;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use Digest::SHA qw(hmac_sha1_base64);

use DJabberd::Plugin::XDisco;

my $domain = "example.com";

my $xd = DJabberd::Plugin::XDisco->new();
$xd->finalize();

my $plugs = [
	    $xd,
	    DJabberd::Delivery::Local->new,
	    DJabberd::Delivery::S2S->new
	];
my $vhost = DJabberd::VHost->new(
	    server_name => $domain,
	    s2s         => 1,
	    plugins     => $plugs,
        );

my ($me, $she) = ('partya', 'partyb');
my ($my, $her) = ('partya@'.$domain.'/test', 'partyb@'.$domain.'/test');

my $res_ok = sub { ok($_[0] =~ /^<iq[^>]+type=['"]result['"]/, $_[0]) };
my $err_ok = sub { ok($_[0] =~ /^<iq[^>]+type=['"]error['"]/, $_[0]) };
my $disco_ok = sub { ok($_[0] =~ /<feature[^>]+(var=['"]urn:xmpp:extdisco:2['"])/m, 'Has feature: '.($1 || $_[0])) };
my $disco_fail = sub { ok($_[0] !~ /<feature[^>]+(var=['"]urn:xmpp:extdisco:2['"])/m, 'No feature') };
my $srvs_ok = sub { ok($_[0] =~ /<services\s+[^>]*xmlns=['"]urn:xmpp:extdisco:2["'][^>]*>(.+)<\/services>/, 'Has services: '.($1 || $_[0])) };


my $test;
my $disco = DJabberd::XMLElement->new('http://jabber.org/protocol/disco#info', 'query', {xmlns=>'http://jabber.org/protocol/disco#info'},[]);
my $xd_all = DJabberd::XMLElement->new('urn:xmpp:extdisco:2', 'services',  { xmlns => 'urn:xmpp:extdisco:2' }, []);
my $creds = DJabberd::XMLElement->new('urn:xmpp:extdisco:2', 'credentials',  { xmlns => 'urn:xmpp:extdisco:2' }, []);
my $turn2 = DJabberd::XMLElement->new(undef, 'service', { '{}type' => 'turn', '{}host' => '1.2.3.4', '{}port' => 9992 }, []);
my $turns = DJabberd::XMLElement->new(undef, 'service', { '{}type' => 'turns', '{}host' => '4.3.2.1' }, []);
my $iq = DJabberd::IQ->new('jabber:client', 'iq',
    {
	xmlns=> 'jabber:client',
	'{}type' => 'get',
	'{}from' => $my,
	'{}to' => $domain,
	'{}id' => 'iq1',
    }, []);
my $fc = FakeCon->new($vhost, DJabberd::JID->new($my), sub { $test->(${$_[1]}) });
$iq->set_connection($fc);

##
# Discover feature advertisement: fail, no services
$iq->push_child($disco);
$test = $disco_fail;
$iq->process($fc);

$xd->add_config_serviceuri('turn:1.2.3.4:9991?transport=udp');
$xd->add_config_serviceuri('turn:1.2.3.4:9992?transport=udp');
$xd->add_config_serviceuri('turns:4.3.2.1:443?transport=tcp');
$xd->add_config_servicecreds('ltc:1.2.3.4?username=anon&password=123');
$xd->add_config_servicecreds('stc:4.3.2.1:443?hmac=sha1&psk=secret');
$xd->finalize();
$vhost = DJabberd::VHost->new(
	    server_name => $domain,
	    s2s         => 1,
	    plugins     => $plugs,
        );
$fc->{vh} = $vhost;
$vhost->register_hook('deliver', sub {
    my ($vh, $cb, $sz) = @_;
    $test->($sz->as_xml);
    $cb->delivered();
});

##
# Discover feature advertisement: ok
$iq->push_child($disco);
$test = $disco_ok;
$iq->process($fc);
$iq->remove_child($disco);


##
# List all services
$iq->push_child($xd_all);
$test = sub {
    $res_ok->(@_);
    $srvs_ok->(@_);
};
$iq->process($fc);

##
# List services of type
$xd_all->set_attr('{}type' => 'turns');
$iq->process($fc);

# reset back
$iq->remove_child($xd_all);

##
# Get credentials for specific service type on host and verify STC type creds
$creds->push_child($turns);
$iq->push_child($creds);
$test = sub {
    $res_ok->(@_);
    $srvs_ok->(@_);
    my $type = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*type=['"]([^'"]+)["']});
    my $host = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*host=['"]([^'"]+)["']});
    my $port = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*(?<!s)port=['"]([^'"]+)["']});
    my $user = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*username=['"]([^'"]+)["']});
    my $pass = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*password=['"]([^'"]+)["']});
    if($user && $pass) {
	my ($time) = split(':',$user);
	my $expired = ($time > time);
	my $pw = hmac_sha1_base64($user, 'secret');
	ok($type eq 'turns', 'Correct type: '.$type);
	ok($host eq '4.3.2.1', 'Correct host: '.$host);
	ok($port == 443, 'Correct port: '.$port);
	ok($pw eq $pass, "Correct password: $pw == $pass");
	ok($time > time, "Not expired: $time > ".time);
    } else {
	fail('No credentials in '.$_[0]);
	fail('No credentials in '.$_[0]);
	fail('No credentials in '.$_[0]);
	fail('No credentials in '.$_[0]);
	fail('No credentials in '.$_[0]);
    }
};
$iq->process($fc);
$creds->remove_child($turns);

##
# Get credentials for specific service type on host and verify LTC type creds
$creds->push_child($turn2);
$test = sub {
    $res_ok->(@_);
    $srvs_ok->(@_);
    my $type = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*type=['"]([^'"]+)["']});
    my $host = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*host=['"]([^'"]+)["']});
    my $port = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*(?<!s)port=['"]([^'"]+)["']});
    my $user = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*username=['"]([^'"]+)["']});
    my $pass = $1 if($_[0] =~ qr{[^/]><service\s+[^>]*password=['"]([^'"]+)["']});
    if($user && $pass) {
	ok($type eq 'turn', 'Correct type: '.$type);
	ok($host eq '1.2.3.4', 'Correct host: '.$host);
	ok($port == 9992, 'Correct port: '.$port);
	ok('anon' eq $user, "Correct username: $user == anon");
	ok('123' eq $pass, "Correct password: $pass == 123");
    } else {
	fail('No credentials in '.$_[0]);
	fail('No credentials in '.$_[0]);
	fail('No credentials in '.$_[0]);
	fail('No credentials in '.$_[0]);
	fail('No credentials in '.$_[0]);
    }
};
$iq->process($fc);
package FakeCon;

sub new {
    bless { vh=>$_[1], jid=>$_[2], wr=>$_[3], xl=>DJabberd::Log->get_logger('FakeCon::XML')}, $_[0];
}

sub is_server { 0 }
sub vhost { $_[0]->{vh} }
sub bound_jid { $_[0]->{jid} }
sub xmllog { $_[0]->{xl} }
sub write { $_[0]->{wr}->(@_) }

sub log_outgoing_data { $_[0]->{xl}->debug($_[1]) }
