package Acme::6502::Tube;

use warnings;
use strict;
use Carp;
use Class::Std;
use Time::HiRes qw(time);
use base qw(Acme::6502);

use version; our $VERSION = qv('0.0.1');

use constant ERROR => 0xF800;

use constant {
    PAGE   => 0x0800,
    HIMEM  => 0x8000
};

use constant {
    OSRDRM => 0xFFB9,
    OSEVEN => 0xFFBF,
    GSINIT => 0xFFC2,
    GSREAD => 0xFFC5,
    NVWRCH => 0xFFC8,
    NVRDCH => 0xFFCB,
    OSFIND => 0xFFCE,
    OSGBPB => 0xFFD1,
    OSBPUT => 0xFFD4,
    OSBGET => 0xFFD7,
    OSARGS => 0xFFDA,
    OSFILE => 0xFFDD,
    OSASCI => 0xFFE3,
    OSNEWL => 0xFFE7,
    OSWRCH => 0xFFEE,
    OSRDCH => 0xFFE0,
    OSWORD => 0xFFF1,
    OSBYTE => 0xFFF4,
    OSCLI  => 0xFFF7
};

my %os : ATTR;

sub BUILD {
    my ($self, $id, $args) = @_;

    my $time_base = time();

    $os{$id} = [ ];

    # Inline OSASCI code
    $self->poke_code(OSASCI,
        0xC9, 0x0D,             # CMP #&0D
        0xD0, 0x07,             # BNE +7
        0xA9, 0x0A,             # LDA #&0A
        0x20, 0xEE, 0xFF,       # JSR &FFEE
        0xA9, 0x0D              # LDA #&0D
    );

    # BRK handler. The interrupt handling is bogus - so don't
    # generate any interrupts before fixing it :)    
    $self->poke_code(0xFF00,
        0x85, 0xFC,
        0x68,
        0x58,
        0x29, 0x10,
        0xF0, 0x17,
        0x8A,
        0x48,
        0xBA,
        0x38,
        0xBD, 0x02, 0x01,
        0xE9, 0x01,
        0x85, 0xFD,
        0xBD, 0x03, 0x01,
        0xE9, 0x00,
        0x85, 0xFE,
        0x68,
        0xAA,
        0x6C, 0x02, 0x02,
        0x6C, 0x04, 0x02
    );

    $self->write_16($self->BREAK, 0xFF00);

    my $oscli = sub {
        my $blk = $self->get_xy();
        my $cmd = '';
        CH: for (;;) {
            my $ch = $self->read_8($blk++);
            last CH if $ch < 0x20;
            $cmd .= chr($ch);
        }
        $cmd =~ s/^[\s\*]+//g;
        if (lc($cmd) eq 'quit') {
            exit;
        } else {
            system($cmd);
        }
    };

    my $osbyte = sub {
        my $a = $self->get_a();
        if ($a == 0x7E) {
            # Ack escape
            $self->write_8(0xFF, 0);
            $self->set_x(0xFF);
        } elsif ($a == 0x82) {
            # Read m/c high order address
            $self->set_xy(0);
        } elsif ($a == 0x83) {
            # Read OSHWM (PAGE)
            $self->set_xy(PAGE);
        } elsif ($a == 0x84) {
            # Read HIMEM
            $self->set_xy(HIMEM);
        } elsif ($a == 0xDA) {
            $self->set_xy(0x0900);
        } else {
            die sprintf("OSBYTE %02x handled\n", $a);
        }
    };

    my $osword = sub {
        my $a   = $self->get_a();
        my $blk = $self->get_xy();

        if ($a == 0x00) {
            # Command line input
            my $buf = $self->read_16($blk);
            my $len = $self->read_8($blk + 2);
            my $min = $self->read_8($blk + 3);
            my $max = $self->read_8($blk + 4);
            my $y = 0;
            if (defined (my $in = <>)) {
                my @c = map ord, split //, $in;
                while (@c && $len-- > 1) {
                    my $c = shift @c;
                    if ($c >= $min && $c <= $max) {
                        $self->write_8($buf + $y++, $c);
                    }
                }
                $self->write_8($buf + $y++, 0x0D);
                $self->set_y($y);
                $self->set_p($self->get_p() & ~$self->C);
            } else {
                # Escape I suppose...
                $self->set_p($self->get_p() | $self->C);
            }
        } elsif ($a == 0x01) {
            # Read clock
            my $now = int((time() - $time_base) * 100);
            $self->write_32($blk, $now);
            $self->write_8($blk + 4, 0);
        } elsif ($a == 0x02) {
            # Set clock
            my $tm = $self->read_32($blk);
            $time_base = time() - ($tm * 100);
        } else {
            die sprintf("OSWORD %02x not handled\n", $a);
        }
    };

    my $oswrch = sub {
        printf("%c", $self->get_a());
    };

    my $osrdch = sub {
        die "OSRDCH not handled\n";
    };

    my $osfile = sub {
        my $a     = $self->get_a();
        my $blk   = $self->get_xy();
        my $name  = $self->read_str($self->read_16($blk));
        my $load  = $self->read_32($blk +  2);
        my $exec  = $self->read_32($blk +  6);
        my $start = $self->read_32($blk + 10);
        my $end   = $self->read_32($blk + 14);

        #printf("%-20s %08x %08x %08x %08x\n", $name, $load, $exec, $start, $end);
        if ($a == 0x00) {
            # Save
            open my $fh, '>', $name or die "Can't write $name\n";
            binmode $fh;
            my $buf = $self->read_chunk($start, $end);
            syswrite $fh, $buf or die "Error writing $name\n";
            $self->set_a(1);
        } elsif ($a == 0xFF) {
            # Load
            if (-f $name) {
                open my $fh, '<', $name or die "Can't read $name\n";
                binmode $fh;
                my $len = -s $fh;
                sysread $fh, my $buf, $len or die "Error reading $name\n";
                $load = PAGE if $exec & 0xFF;
                $self->write_chunk($load, $buf);
                $self->write_32($blk +  2, $load);
                $self->write_32($blk +  6, 0x00008023);
                $self->write_32($blk + 10, $len);
                $self->write_32($blk + 14, 0x00000000);
                $self->set_a(1);
            } elsif (-d $name) {
                $self->set_a(2);
            } else {
                $self->set_a(0);
            }
        } else {
            die sprintf("OSFILE %02x not handled\n", $a);
        }
    };

    my $osargs = sub {
        die "OSARGS not handled\n";
    };

    my $osbget = sub {
        die "OSBGET not handled\n";
    };

    my $osbput = sub {
        die "OSBPUT not handled\n";
    };

    my $osgbpb = sub {
        die "OSGBPB not handled\n";
    };

    my $osfind = sub {
        die "OSFIND not handled\n";
    };

    my $make_vector = sub {
        my ($addr, $vec, $code) = @_;
        my $vecno = scalar @{$os{$id}};
        push @{$os{$id}}, $code;
        $self->make_vector($addr, $vec, $vecno);
    };

    $make_vector->(OSCLI,  0x208, $oscli);
    $make_vector->(OSBYTE, 0x20A, $osbyte);
    $make_vector->(OSWORD, 0x20C, $osword);
    $make_vector->(OSWRCH, 0x20E, $oswrch);
    $make_vector->(OSRDCH, 0x210, $osrdch);
    $make_vector->(OSFILE, 0x212, $osfile);
    $make_vector->(OSARGS, 0x214, $osargs);
    $make_vector->(OSBGET, 0x216, $osbget);
    $make_vector->(OSBPUT, 0x218, $osbput);
    $make_vector->(OSGBPB, 0x21A, $osgbpb);
    $make_vector->(OSFIND, 0x21C, $osfind);    
}

# load_rom('BASIC2.rom', 0x8000);
# $pc = 0x8000;
# $a  = 0x01;
# $s  = 0xFF;
# $p  = 0x22;
# run(2000_000) while 1;
# #trace(2000_000);

sub call_os {
    my $self = shift;
    my $id   = ident($self);
    my $i    = shift;

    eval {
        die "Bad OS call $i\n"
            unless exists $os{$id}->[$i];
        $os{$id}->[$i]->();
    };

    if ($@) {
        my $err = $@;
        $self->write_16(ERROR, 0x7F00);
        $err =~ s/\s+/ /;
        $err =~ s/^\s+//;
        $err =~ s/\s+$//;
        my $ep = ERROR + 2;
        for (map ord, split //, $err) {
            $self->write_8($ep++, $_);
        }
        $self->write_8($ep++, 0x00);
        $self->set_pc(ERROR);
    }
}

1;
__END__

=head1 NAME

Acme::6502 - Pure Perl 65C02 simulator.

=head1 VERSION

This document describes Acme::6502 version 0.0.1

=head1 SYNOPSIS

    use Acme::6502;

=for author to fill in:
    Brief code example(s) here showing commonest usage(s).
    This section will be as far as many users bother reading
    so make it as educational and exeplary as possible.
  
=head1 DESCRIPTION

=for author to fill in:
    Write a full description of the module and its features here.
    Use subsections (=head2, =head3) as appropriate.

=head1 INTERFACE 

=over

=item C<call_os()>

=back

=for author to fill in:
    List every single error and warning message that the module can
    generate (even the ones that will "never happen"), with a full
    explanation of each problem, one or more likely causes, and any
    suggested remedies.

=over

=item C<< Error message here, perhaps with %s placeholders >>

[Description of error here]

=item C<< Another error message here >>

[Description of error here]

[Et cetera, et cetera]

=back

=head1 CONFIGURATION AND ENVIRONMENT

=for author to fill in:
    A full explanation of any configuration system(s) used by the
    module, including the names and locations of any configuration
    files, and the meaning of any environment variables or properties
    that can be set. These descriptions must also include details of any
    configuration language used.
  
Acme::6502 requires no configuration files or environment variables.

=head1 DEPENDENCIES

=for author to fill in:
    A list of all the other modules that this module relies upon,
    including any restrictions on versions, and an indication whether
    the module is part of the standard Perl distribution, part of the
    module's distribution, or must be installed separately. ]

None.

=head1 INCOMPATIBILITIES

=for author to fill in:
    A list of any modules that this module cannot be used in conjunction
    with. This may be due to name conflicts in the interface, or
    competition for system or program resources, or due to internal
    limitations of Perl (for example, many modules that use source code
    filters are mutually incompatible).

None reported.

=head1 BUGS AND LIMITATIONS

=for author to fill in:
    A list of known problems with the module, together with some
    indication Whether they are likely to be fixed in an upcoming
    release. Also a list of restrictions on the features the module
    does provide: data types that cannot be handled, performance issues
    and the circumstances in which they may arise, practical
    limitations on the size of data sets, special cases that are not
    (yet) handled, etc.

No bugs have been reported.

Please report any bugs or feature requests to
C<bug-acme-6502@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.

=head1 AUTHOR

Andy Armstrong  C<< <andy@hexten.net> >>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2006, Andy Armstrong C<< <andy@hexten.net> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.

=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.
