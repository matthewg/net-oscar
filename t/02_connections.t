#!/usr/bin/perl

# The Connection modules are loaded on demand,
# so we test loading them all here.

use Test::More tests => 5;
use strict;
use warnings;
use lib "./blib/lib";

require_ok('Net::OSCAR');
require_ok('Net::OSCAR::Connection');
require_ok('Net::OSCAR::Connection::Direct');
require_ok('Net::OSCAR::Connection::Chat');
require_ok('Net::OSCAR::Connection::Server');

1;
