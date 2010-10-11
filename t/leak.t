use strict;
use warnings;

use Test::More;
use Acme::6502;

eval { require Test::LeakTrace; };

plan skip_all => "Test::LeakTrace require for this test" if $@;

Test::LeakTrace::no_leaks_ok( sub {
    my $cpu = Acme::6502->new;
} );

done_testing;
