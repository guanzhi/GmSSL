# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

package with_fallback;

sub import {
    use File::Basename;
    use File::Spec::Functions;
    foreach (@_) {
	eval "require $_";
	if ($@) {
	    unshift @INC, catdir(dirname(__FILE__), "..", "external", "perl");
	    my $transfer = "transfer::$_";
	    eval "require $transfer";
	    shift @INC;
	    warn $@ if $@;
	}
    }
}
1;
