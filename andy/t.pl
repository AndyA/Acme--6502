#!/usr/bin/env perl

use strict;
use warnings;
use Data::Dumper;
use lib qw(lib);
use Acme::6502;
use Acme::6502::Tube;

$| = 1;

my $cpu = Acme::6502::Tube->new();

my $trace = sub {
  my $pos  = shift;
  my $name = shift;
  my ( $a, $x, $y, $s, $p, $pc ) = $cpu->get_state();
  $p = $cpu->decode_flags( $p );
  warn sprintf( "%6s %6s %02x %02x %02x %02x %8s %04x\n",
    $pos, $name, $a, $x, $y, $s, $p, $pc );
};

#$cpu->connect('pre_os',  sub { $trace->('before', @_); });
#$cpu->connect('post_os', sub { $trace->('after',  @_);  });

my $rom = shift || 'Roms/Forth-2.5.rom';

#$cpu->load_rom('BASIC2.rom', 0x8000);
$cpu->load_rom( $rom, 0x8000 );
$cpu->set_pc( 0x8000 );
$cpu->set_a( 0x01 );
$cpu->set_s( 0xFF );
$cpu->set_p( 0x22 );
$cpu->run( 2000_000 ) while 1;
