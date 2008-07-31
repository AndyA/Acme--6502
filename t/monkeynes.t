use strict;
use warnings;

use Test::More 'no_plan';

BEGIN {
    use_ok( 'Acme::6502' );
}

my %test_lut = (
    m => sub {
        my $diag = "Mem[\$$_[1]]=$_[2]";
        is shift->read_8( hex shift ), hex shift, $diag;
    },
    ps => sub {
        my $diag = "PS=$_[1]";
        is shift->get_p, hex shift, $diag;
    },
    pc => sub {
        my $diag = "PC=$_[1]";
        is shift->get_pc, hex shift, $diag;
    },
    sp => sub {
        my $diag = "SP=$_[1]";
        is shift->get_s, hex shift, $diag;
    },
    acc => sub {
        my $diag = "ACC=$_[1]";
        is shift->get_a, hex shift, $diag;
    },
    ix => sub {
        my $diag = "IX=$_[1]";
        is shift->get_x, hex shift, $diag;
    },
    iy => sub {
        my $diag = "IY=$_[1]";
        is shift->get_y, hex shift, $diag;
    },
    s => sub {
        my $cpu = shift;
        my $diag = "N=$_[0]";
        is( $cpu->get_p & $cpu->N ? 1 : 0, shift, $diag );
    },
    v => sub {
        my $cpu = shift;
        my $diag = "V=$_[0]";
        is( $cpu->get_p & $cpu->V ? 1 : 0, shift, $diag );
    },
    b => sub {
        my $cpu = shift;
        my $diag = "B=$_[0]";
        is( $cpu->get_p & $cpu->B ? 1 : 0, shift, $diag );
    },
    d => sub {
        my $cpu = shift;
        my $diag = "D=$_[0]";
        is( $cpu->get_p & $cpu->D ? 1 : 0, shift, $diag );
    },
    i => sub {
        my $cpu = shift;
        my $diag = "I=$_[0]";
        is( $cpu->get_p & $cpu->I ? 1 : 0, shift, $diag );
    },
    z => sub {
        my $cpu = shift;
        my $diag = "Z=$_[0]";
        is( $cpu->get_p & $cpu->Z ? 1 : 0, shift, $diag );
    },
    c => sub {
        my $cpu = shift;
        my $diag = "C=$_[0]";
        is( $cpu->get_p & $cpu->C ? 1 : 0, shift, $diag );
    },
);

my $glob = $ENV{TEST_OP} || '*';
my @files = glob( "t/monkeynes/script_${glob}.txt" );

for my $file ( @files ) {
    open( my $script, $file ) || die qq(cannot load test script "$file");
    diag( qq(Running script "$file") );
    my @lines = <$script>;
    chomp( @lines );
    run_script( @lines );
    close( $script );
    exit;
}

sub run_script {
    my $cpu;
    for( @_ ) {
        chomp;
        next if m{^\s*$};
        next if m{^save};
        if( m{^# (.+)} ) {
            diag( $1 );
        }
        elsif( $_ eq 'clear' ) {
            next;
        }
        elsif( $_ eq 'power on' ) {
            $cpu = Acme::6502->new();
            $cpu->set_s( 255 );
            $cpu->set_p( $cpu->get_p | $cpu->R );
            isa_ok( $cpu, 'Acme::6502' );
        }
        elsif( $_ eq 'memclear' ) {
            $cpu->poke_code( 0, ( 0 ) x 65536 );
            diag( 'Mem cleared' );
        }
        elsif( m{^regs(?: (.+))?} ) {
            diag_regs( $cpu, $1 );
        }
        elsif( m{^memset (.+) (.+)} ) {
            $cpu->write_8( hex $1, hex $2 );
            is( $cpu->read_8( hex $1 ), hex $2, "Mem[$1] set to $2" );
        }
        elsif( m{^test (.+) = (.+)} ) {
            my( $op, @args ) = ( split( /:/, $1 ), $2 );
            $test_lut{ $op }->( $cpu, @args );
        }
        elsif( m{^op (.+)} ) {
            my( $op, $args_hex ) = split(' ', $1 );
            diag( "OP: $1" );
            $args_hex = '' unless defined $args_hex;
            my @args = ( $args_hex =~ m{(..)}g );
            my $pc = hex(8000);
            $cpu->poke_code( $pc, map { hex( $_ || 0 ) } $op, @args[0..1] );
            $cpu->set_pc( $pc );
            $cpu->run(1);
        }
        else {
            use Data::Dumper;
            warn Dumper $_;
        }
    }
}

sub diag_regs {
    my $cpu = shift;
    my $reg = uc shift;

    diag( 'CPU Registers' ) if !$reg;
    diag( sprintf '  PC:    $%X', $cpu->get_pc ) if !$reg || $reg eq 'PC';
    diag( sprintf '  SP:    $%X', $cpu->get_s ) if !$reg || $reg eq 'SP';
    diag( sprintf '  ACC:   $%X', $cpu->get_a ) if !$reg || $reg eq 'ACC';
    diag( sprintf '  IX:    $%X', $cpu->get_x ) if !$reg || $reg eq 'IX';
    diag( sprintf '  IY:    $%X', $cpu->get_y ) if !$reg || $reg eq 'IY';
    # this should be fixed to handle just one flag at a time
    diag( '  Flags  S V - B D I Z C' ) if !$reg || $reg =~ m{^(PS|[SVBDIZC])$};
    diag( sprintf '  PS:    %d %d %d %d %d %d %d %d',
        split( //, sprintf( '%08b', $cpu->get_p ) )
    ) if !$reg || $reg =~ m{^(PS|[SVBDIZC])$};
}
