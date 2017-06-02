# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;

package TLSProxy::ServerHello;

use vars '@ISA';
push @ISA, 'TLSProxy::Message';

sub new
{
    my $class = shift;
    my ($server,
        $data,
        $records,
        $startoffset,
        $message_frag_lens) = @_;
    
    my $self = $class->SUPER::new(
        $server,
        TLSProxy::Message::MT_SERVER_HELLO,
        $data,
        $records,
        $startoffset,
        $message_frag_lens);

    $self->{server_version} = 0;
    $self->{random} = [];
    $self->{session_id_len} = 0;
    $self->{session} = "";
    $self->{ciphersuite} = 0;
    $self->{comp_meth} = 0;
    $self->{extension_data} = "";

    return $self;
}

sub parse
{
    my $self = shift;
    my $ptr = 2;
    my ($server_version) = unpack('n', $self->data);
    my $random = substr($self->data, $ptr, 32);
    $ptr += 32;
    my $session_id_len = unpack('C', substr($self->data, $ptr));
    $ptr++;
    my $session = substr($self->data, $ptr, $session_id_len);
    $ptr += $session_id_len;
    my $ciphersuite = unpack('n', substr($self->data, $ptr));
    $ptr += 2;
    my $comp_meth = unpack('C', substr($self->data, $ptr));
    $ptr++;
    my $extensions_len = unpack('n', substr($self->data, $ptr));
    if (!defined $extensions_len) {
        $extensions_len = 0;
    } else {
        $ptr += 2;
    }
    #For now we just deal with this as a block of data. In the future we will
    #want to parse this
    my $extension_data;
    if ($extensions_len != 0) {
        $extension_data = substr($self->data, $ptr);
    
        if (length($extension_data) != $extensions_len) {
            die "Invalid extension length\n";
        }
    } else {
        if (length($self->data) != $ptr) {
            die "Invalid extension length\n";
        }
        $extension_data = "";
    }
    my %extensions = ();
    while (length($extension_data) >= 4) {
        my ($type, $size) = unpack("nn", $extension_data);
        my $extdata = substr($extension_data, 4, $size);
        $extension_data = substr($extension_data, 4 + $size);
        $extensions{$type} = $extdata;
    }

    $self->server_version($server_version);
    $self->random($random);
    $self->session_id_len($session_id_len);
    $self->session($session);
    $self->ciphersuite($ciphersuite);
    $self->comp_meth($comp_meth);
    $self->extension_data(\%extensions);

    $self->process_data();

    print "    Server Version:".$server_version."\n";
    print "    Session ID Len:".$session_id_len."\n";
    print "    Ciphersuite:".$ciphersuite."\n";
    print "    Compression Method:".$comp_meth."\n";
    print "    Extensions Len:".$extensions_len."\n";
}

#Perform any actions necessary based on the data we've seen
sub process_data
{
    my $self = shift;

    TLSProxy::Message->ciphersuite($self->ciphersuite);
}

#Reconstruct the on-the-wire message data following changes
sub set_message_contents
{
    my $self = shift;
    my $data;
    my $extensions = "";

    $data = pack('n', $self->server_version);
    $data .= $self->random;
    $data .= pack('C', $self->session_id_len);
    $data .= $self->session;
    $data .= pack('n', $self->ciphersuite);
    $data .= pack('C', $self->comp_meth);

    foreach my $key (keys %{$self->extension_data}) {
        my $extdata = ${$self->extension_data}{$key};
        $extensions .= pack("n", $key);
        $extensions .= pack("n", length($extdata));
        $extensions .= $extdata;
        if ($key == TLSProxy::Message::EXT_DUPLICATE_EXTENSION) {
          $extensions .= pack("n", $key);
          $extensions .= pack("n", length($extdata));
          $extensions .= $extdata;
        }
    }

    $data .= pack('n', length($extensions));
    $data .= $extensions;
    $self->data($data);
}

#Read/write accessors
sub server_version
{
    my $self = shift;
    if (@_) {
      $self->{client_version} = shift;
    }
    return $self->{client_version};
}
sub random
{
    my $self = shift;
    if (@_) {
      $self->{random} = shift;
    }
    return $self->{random};
}
sub session_id_len
{
    my $self = shift;
    if (@_) {
      $self->{session_id_len} = shift;
    }
    return $self->{session_id_len};
}
sub session
{
    my $self = shift;
    if (@_) {
      $self->{session} = shift;
    }
    return $self->{session};
}
sub ciphersuite
{
    my $self = shift;
    if (@_) {
      $self->{ciphersuite} = shift;
    }
    return $self->{ciphersuite};
}
sub comp_meth
{
    my $self = shift;
    if (@_) {
      $self->{comp_meth} = shift;
    }
    return $self->{comp_meth};
}
sub extension_data
{
    my $self = shift;
    if (@_) {
      $self->{extension_data} = shift;
    }
    return $self->{extension_data};
}
sub set_extension
{
    my ($self, $ext_type, $ext_data) = @_;
    $self->{extension_data}{$ext_type} = $ext_data;
}
sub delete_extension
{
    my ($self, $ext_type) = @_;
    delete $self->{extension_data}{$ext_type};
}
1;
