use strict;
use warnings;
use Test::More;
use Test::LeakTrace;

use Acme::6502;

no_leaks_ok {
    my $cpu = Acme::6502->new;
};

done_testing;
