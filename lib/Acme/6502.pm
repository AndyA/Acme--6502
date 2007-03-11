package Acme::6502;

use warnings FATAL => 'all';
use strict;
use Carp;
use Class::Std;

use version; our $VERSION = qv('0.0.6');

# CPU flags
use constant {
    N => 0x80,
    V => 0x40,
    R => 0x20,
    B => 0x10,
    D => 0x08,
    I => 0x04,
    Z => 0x02,
    C => 0x01
};

use constant FLAGS => 'NVRBDIZC';
 
# Other CPU constants
use constant {
    STACK => 0x0100,
    BREAK => 0xFFFE
};

# Opcode to thunk into perlspace
use constant {
    ESCAPE_OP  => 0x0B,
    ESCAPE_SIG => 0xAD
};

my %cpu : ATTR;

sub BUILD {
    my ($self, $id, $args) = @_;

    my @mem = (0) x 65536;
    my @os;
    my ($a, $x, $y, $s, $p, $pc) = (0) x 6;

    # Page used to allocate vector thunks
    my $jumptab = $args->{jumptab} || 0xFA00;

    my $bad_inst = sub {
        croak sprintf("Bad instruction at &%04x (&%02x)\n",
            $pc - 1, $mem[$pc - 1]);
    };

    my @zn = (Z, (0) x 127, (N) x 128);

    my $inst = sub {
        my $src = join("\n", @_);
        my $cr = eval "sub { @_ }";
        confess "$@" if $@;
        return $cr;
    };

    my @decode = (
        $inst->(                               # 00 BRK
            _push('($pc + 1) >> 8', '($pc + 1)'),
            _push('$p | B'),
            '$p = $p | I & ~D;',
            _jmp_i(BREAK)
        ),
        $inst->(_ora(_zpix())),                # 01 ORA (zp, x)
        $bad_inst,                             # 02
        $bad_inst,                             # 03
        $inst->(_tsb(_zp())),                  # 04 TSB zp
        $inst->(_ora(_zp())),                  # 05 ORA zp
        $inst->(_asl(_zp())),                  # 06 ASL zp
        $bad_inst,                             # 07
        $inst->(_push('$p | R')),              # 08 PHP
        $inst->(_ora(_imm())),                 # 09 ORA #imm
        $inst->(_asl(_acc())),                 # 0A ASL A
        $bad_inst,                             # 0B
        $inst->(_tsb(_abs())),                 # 0C TSB zp
        $inst->(_ora(_abs())),                 # 0D ORA abs
        $inst->(_asl(_abs())),                 # 0E ASL abs
        $bad_inst,                             # 0F BBR0 rel
        $inst->(_bfz(_rel(), N)),              # 10 BPL rel
        $inst->(_ora(_zpiy())),                # 11 ORA (zp), y
        $inst->(_ora(_zpi())),                 # 12 ORA (zp)
        $bad_inst,                             # 13
        $inst->(_trb(_zpi())),                 # 14 TRB (zp)
        $inst->(_ora(_zpx())),                 # 15 ORA zp, x
        $inst->(_asl(_zpx())),                 # 16 ASL zp, x
        $bad_inst,                             # 17
        $inst->('$p &= ~C;'),                  # 18 CLC
        $inst->(_ora(_absy())),                # 19 ORA abs, y
        $inst->(_inc(_acc())),                 # 1A INC A
        $bad_inst,                             # 1B
        $inst->(_trb(_abs())),                 # 1C TRB abs
        $inst->(_ora(_absx())),                # 1D ORA abs, x
        $inst->(_asl(_absx())),                # 1E ASL abs, x
        $bad_inst,                             # 1F BBR1 rel
        $inst->(                               # 20 JSR
            _push('($pc + 1) >> 8', '($pc + 1)'),
            _jmp()
        ),
        $inst->(_and(_zpix())),                # 21 AND (zp, x)
        $bad_inst,                             # 22
        $bad_inst,                             # 23
        $inst->(_bit(_zp())),                  # 24 BIT zp
        $inst->(_and(_zp())),                  # 25 AND zp
        $inst->(_rol(_zp())),                  # 26 ROL zp
        $bad_inst,                             # 27
        $inst->(_pop_p()),                     # 28 PLP
        $inst->(_and(_imm())),                 # 29 AND  #imm
        $inst->(_rol(_acc())),                 # 2A ROL A
        $bad_inst,                             # 2B
        $inst->(_bit(_abs())),                 # 2C BIT abs
        $inst->(_and(_abs())),                 # 2D AND abs
        $inst->(_rol(_abs())),                 # 2E ROL abs
        $bad_inst,                             # 2F BBR2 rel
        $inst->(_bfnz(_rel(), N)),             # 30 BPL rel
        $inst->(_and(_zpiy())),                # 31 AND (zp), y
        $inst->(_and(_zpi())),                 # 32 AND (zp)
        $bad_inst,                             # 33
        $inst->(_bit(_zpx())),                 # 34 BIT zp, x
        $inst->(_and(_zpx())),                 # 35 AND zp, x
        $inst->(_rol(_zpx())),                 # 36 ROL zp, x
        $bad_inst,                             # 37
        $inst->('$p |= C;'),                   # 38 SEC
        $inst->(_and(_absy())),                # 39 AND abs, y
        $inst->(_dec(_acc())),                 # 3A DEC A
        $bad_inst,                             # 3B
        $inst->(_bit(_absx())),                # 3C BIT abs, x
        $inst->(_and(_absx())),                # 3D AND abs, x
        $inst->(_rol(_absx())),                # 3E ROL abs, x
        $bad_inst,                             # 3F BBR3 rel
        $inst->(_pop('$p'), _rts()),           # 40 RTI
        $inst->(_eor(_zpix())),                # 41 EOR (zp, x)
        $bad_inst,                             # 42
        $bad_inst,                             # 43
        $bad_inst,                             # 44
        $inst->(_eor(_zp())),                  # 45 EOR zp
        $inst->(_lsr(_zp())),                  # 46 LSR zp
        $bad_inst,                             # 47
        $inst->(_push('$a')),                  # 48 PHA
        $inst->(_eor(_imm())),                 # 49 EOR imm
        $inst->(_lsr(_acc())),                 # 4A LSR A
        $bad_inst,                             # 4B
        $inst->(_jmp()),                       # 4C JMP abs
        $inst->(_eor(_abs())),                 # 4D EOR abs
        $inst->(_lsr(_abs())),                 # 4E LSR abs
        $bad_inst,                             # 4F BBR4 rel
        $inst->(_bfz(_rel(), V)),              # 50 BVC rel
        $inst->(_eor(_zpiy())),                # 51 EOR (zp), y
        $inst->(_eor(_zpi())),                 # 52 EOR (zp)
        $bad_inst,                             # 53
        $bad_inst,                             # 54
        $inst->(_eor(_zpx())),                 # 55 EOR zp, x
        $inst->(_lsr(_zpx())),                 # 56 LSR zp, x
        $bad_inst,                             # 57
        $inst->('$p &= ~I;'),                  # 58 CLI
        $inst->(_eor(_absy())),                # 59 EOR abs, y
        $inst->(_push('$y')),                  # 5A PHY
        $bad_inst,                             # 5B
        $bad_inst,                             # 5C
        $inst->(_eor(_absx())),                # 5D EOR abs, x
        $inst->(_lsr(_absx())),                # 5E LSR abs, x
        $bad_inst,                             # 5F BBR5 rel
        $inst->(_rts()),                       # 60 RTS
        $inst->(_adc(_zpx())),                 # 61 ADC zp, x
        $bad_inst,                             # 62
        $bad_inst,                             # 63
        $inst->(_sto(_zp(), '0')),             # 64 STZ zp
        $inst->(_adc(_zp())),                  # 65 ADC zp
        $inst->(_ror(_zp())),                  # 66 ROR zp
        $bad_inst,                             # 67
        $inst->(_pop('$a'), _status('$a')),    # 68 PLA
        $inst->(_adc(_imm())),                 # 69 ADC  #imm
        $inst->(_ror(_acc())),                 # 6A ROR A
        $bad_inst,                             # 6B
        $inst->(_jmpi()),                      # 6C JMP (abs)
        $inst->(_adc(_abs())),                 # 6D ADC abs
        $inst->(_ror(_abs())),                 # 6E ROR abs
        $bad_inst,                             # 6F BBR6 rel
        $inst->(_bfnz(_rel(), V)),             # 70 BVS rel
        $inst->(_adc(_zpiy())),                # 71 ADC (zp), y
        $inst->(_adc(_zpi())),                 # 72 ADC (zp)
        $bad_inst,                             # 73
        $inst->(_sto(_zpx(), '0')),            # 74 STZ zp, x
        $inst->(_adc(_zpx())),                 # 75 ADC zp, x
        $inst->(_adc(_zpx())),                 # 76 ROR zp, x
        $bad_inst,                             # 77
        $inst->('$p |= I;'),                   # 78 STI
        $inst->(_adc(_absy())),                # 79 ADC abs, y
        $inst->(_pop('$y'), _status('$y')),    # 7A PLY
        $bad_inst,                             # 7B
        $inst->(_jmpix()),                     # 7C JMP (abs, x)
        $inst->(_adc(_absx())),                # 7D ADC abs, x
        $inst->(_ror(_absx())),                # 7E ROR abs, x
        $bad_inst,                             # 7F BBR7 rel
        $inst->(_bra(_rel())),                 # 80 BRA rel
        $inst->(_sto(_zpix(), '$a')),          # 81 STA (zp, x)
        $bad_inst,                             # 82
        $bad_inst,                             # 83
        $inst->(_sto(_zp(), '$y')),            # 84 STY zp
        $inst->(_sto(_zp(), '$a')),            # 85 STA zp
        $inst->(_sto(_zp(), '$x')),            # 86 STX zp
        $bad_inst,                             # 87
        $inst->(_dec(('', '$y'))),             # 88 DEY
        $inst->(_bit(_imm())),                 # 89 BIT  #imm
        $inst->('$a = $x;' . _status('$a')),   # 8A TXA
        $bad_inst,                             # 8B
        $inst->(_sto(_abs(), '$y')),           # 8C STY abs
        $inst->(_sto(_abs(), '$a')),           # 8D STA abs
        $inst->(_sto(_abs(), '$x')),           # 8E STX abs
        $bad_inst,                             # 8F BBS0 rel
        $inst->(_bfz(_rel(), C)),              # 90 BCC rel
        $inst->(_sto(_zpiy(), '$a')),          # 91 STA (zp), y
        $inst->(_sto(_zpi(),  '$a')),          # 92 STA (zp)
        $bad_inst,                             # 93
        $inst->(_sto(_zpx(), '$y')),           # 94 STY zp, x
        $inst->(_sto(_zpx(), '$a')),           # 95 STA zp, x
        $inst->(_sto(_zpy(), '$x')),           # 96 STX zp, y
        $bad_inst,                             # 97
        $inst->('$a = $y;' . _status('$a')),   # 98 TYA
        $inst->(_sto(_absy(), '$a')),          # 99 STA abs, y
        $inst->('$s = $x;'),                   # 9A TXS
        $bad_inst,                             # 9B
        $inst->(_sto(_abs(),  '0')),           # 9C STZ abs
        $inst->(_sto(_absx(), '$a')),          # 9D STA abs, x
        $inst->(_sto(_absx(), '0')),           # 9E STZ abs, x
        $bad_inst,                             # 9F BBS1 rel
        $inst->(_lod(_imm(),  '$y')),          # A0 LDY  #imm
        $inst->(_lod(_zpix(), '$a')),          # A1 LDA (zp, x)
        $inst->(_lod(_imm(),  '$x')),          # A2 LDX  #imm
        $bad_inst,                             # A3
        $inst->(_lod(_zp(), '$y')),            # A4 LDY zp
        $inst->(_lod(_zp(), '$a')),            # A5 LDA zp
        $inst->(_lod(_zp(), '$x')),            # A6 LDX zp
        $bad_inst,                             # A7
        $inst->('$y = $a;' . _status('$y')),   # A8 TAY
        $inst->(_lod(_imm(), '$a')),           # A9 LDA  #imm
        $inst->('$x = $a;' . _status('$x')),   # AA TAX
        $bad_inst,                             # AB
        $inst->(_lod(_abs(), '$y')),           # AC LDY abs
        $inst->(_lod(_abs(), '$a')),           # AD LDA abs
        $inst->(_lod(_abs(), '$x')),           # AE LDX abs
        $bad_inst,                             # AF BBS2 rel
        $inst->(_bfnz(_rel(), C)),             # B0 BCS rel
        $inst->(_lod(_zpiy(), '$a')),          # B1 LDA (zp), y
        $inst->(_lod(_zpi(),  '$a')),          # B2 LDA (zp)
        $bad_inst,                             # B3
        $inst->(_lod(_zpx(), '$y')),           # B4 LDY zp, x
        $inst->(_lod(_zpx(), '$a')),           # B5 LDA zp, x
        $inst->(_lod(_zpy(), '$x')),           # B6 LDX zp, y
        $bad_inst,                             # B7
        $inst->('$p &= ~V;'),                  # B8 CLV
        $inst->(_lod(_absy(), '$a')),          # B9 LDA abs, y
        $inst->('$x = $s;'),                   # BA TSX
        $bad_inst,                             # BB
        $inst->(_lod(_absx(), '$y')),          # BC LDY abs, x
        $inst->(_lod(_absx(), '$a')),          # BD LDA abs, x
        $inst->(_lod(_absy(), '$x')),          # BE LDX abs, y
        $bad_inst,                             # BF BBS3 rel
        $inst->(_cmp(_imm(),  '$y')),          # C0 CPY  #imm
        $inst->(_cmp(_zpix(), '$a')),          # C1 CMP (zp, x)
        $bad_inst,                             # C2
        $bad_inst,                             # C3
        $inst->(_cmp(_zp(), '$y')),            # C4 CPY zp
        $inst->(_cmp(_zp(), '$a')),            # C5 CMP zp
        $inst->(_dec(_zp())),                  # C6 DEC zp
        $bad_inst,                             # C7
        $inst->(_inc(('', '$y'))),             # C8 INY
        $inst->(_cmp(_imm(), '$a')),           # C9 CMP  #imm
        $inst->(_dec(('', '$x'))),             # CA DEX
        $bad_inst,                             # CB
        $inst->(_cmp(_abs(), '$y')),           # CC CPY abs
        $inst->(_cmp(_abs(), '$a')),           # CD CMP abs
        $inst->(_dec(_abs())),                 # CE DEC abs
        $bad_inst,                             # CF BBS4 rel
        $inst->(_bfz(_rel(), Z)),              # D0 BNE rel
        $inst->(_cmp(_zpiy(), '$a')),          # D1 CMP (zp), y
        $inst->(_cmp(_zpi(),  '$a')),          # D2 CMP (zp)
        $bad_inst,                             # D3
        $bad_inst,                             # D4
        $inst->(_cmp(_zpx(), '$a')),           # D5 CMP zp, x
        $inst->(_dec(_zpx())),                 # D6 DEC zp, x
        $bad_inst,                             # D7
        $inst->('$p &= ~D;'),                  # D8 CLD
        $inst->(_cmp(_absy(), '$a')),          # D9 CMP abs, y
        $inst->(_push('$x')),                  # DA PHX
        $bad_inst,                             # DB
        $bad_inst,                             # DC
        $inst->(_cmp(_absx(), '$a')),          # DD CMP abs, x
        $inst->(_dec(_absx())),                # DE DEC abs, x
        $bad_inst,                             # DF BBS5 rel
        $inst->(_cmp(_imm(), '$x')),           # E0 CPX  #imm
        $inst->(_sbc(_zpix(), '$a')),          # E1 SBC (zp, x)
        $bad_inst,                             # E2
        $bad_inst,                             # E3
        $inst->(_cmp(_zp(), '$x')),            # E4 CPX zp
        $inst->(_sbc(_zp())),                  # E5 SBC zp
        $inst->(_inc(_zp())),                  # E6 INC zp
        $bad_inst,                             # E7
        $inst->(_inc(('', '$x'))),             # E8 INX
        $inst->(_sbc(_imm())),                 # E9 SBC  #imm
        $inst->(),                             # EA NOP
        $bad_inst,                             # EB
        $inst->(_cmp(_abs(), '$x')),           # EC CPX abs
        $inst->(_sbc(_abs())),                 # ED SBC abs
        $inst->(_inc(_abs())),                 # EE INC abs
        $bad_inst,                             # EF BBS6 rel
        $inst->(_bfnz(_rel(), Z)),             # F0 BEQ rel
        $inst->(_sbc(_zpiy())),                # F1 SBC (zp), y
        $inst->(_sbc(_zpi())),                 # F2 SBC (zp)
        $bad_inst,                             # F3
        $bad_inst,                             # F4
        $inst->(_sbc(_zpx())),                 # F5 SBC zp, x
        $inst->(_inc(_zpx())),                 # F6 INC zp, x
        $bad_inst,                             # F7
        $inst->('$p |= D;'),                   # F8 SED
        $inst->(_sbc(_absy())),                # F9 SBC abs, y
        $inst->(_pop('$x'), _status('$x')),    # FA PLX
        $bad_inst,                             # FB
        $bad_inst,                             # FC
        $inst->(_sbc(_absx())),                # FD SBC abs, x
        $inst->(_inc(_absx())),                # FE INC abs, x
        $bad_inst                              # FF BBS7 rel
    );

    confess "Escape handler opcode not available"
        unless $decode[ESCAPE_OP] == $bad_inst;

    # Patch in the OS escape op handler
    $decode[ESCAPE_OP] = sub {
        if ($mem[$pc] != ESCAPE_SIG) {
            $bad_inst->();
        } else {
            $pc += 2;
            $self->call_os($mem[$pc - 1]);
        }
    };

    $cpu{$id} = {
        set_jumptab => sub {
            $jumptab = shift;
        },
        
        read_str => sub {
            my $addr = shift;
            my $str  = '';
            while ($mem[$addr] != 0x0D) {
                $str .= chr($mem[$addr++]);
            }
            return $str;
        },

        read_chunk => sub {
            my ($from, $to) = @_;
            return pack('C*', @mem[$from .. $to - 1]);
        },

        write_chunk => sub {
            my ($addr, $chunk) = @_;
            my $len = length($chunk);
            splice @mem, $addr, $len, unpack('C*', $chunk);
        },

        read_8 => sub {
            my $addr = shift;
            return $mem[$addr];
        },

        write_8 => sub {
            my ($addr, $val) = @_;
            $mem[$addr] = $val;
        },

        read_16 => sub {
            my $addr = shift;
            return $mem[$addr] | ($mem[$addr + 1] << 8);
        },

        write_16 => sub {
            my ($addr, $val) = @_;
            $mem[$addr + 0] = ($val >> 0) & 0xFF;
            $mem[$addr + 1] = ($val >> 8) & 0xFF;
        },

        read_32 => sub {
            my $addr = shift;
            return $mem[$addr] | ($mem[$addr + 1] << 8) |
                ($mem[$addr + 2] << 16) | ($mem[$addr + 3] << 32);
        },

        write_32 => sub {
            my ($addr, $val) = @_;
            $mem[$addr + 0] = ($val >>  0) & 0xFF;
            $mem[$addr + 1] = ($val >>  8) & 0xFF;
            $mem[$addr + 2] = ($val >> 16) & 0xFF;
            $mem[$addr + 3] = ($val >> 24) & 0xFF;
        },

        run => sub {
            my $ic = shift;
            my $cb = shift;
            if (defined($cb)) {
                while ($ic-- > 0) {
                    $cb->($pc, $mem[$pc], $a, $x, $y, $s, $p);
                    $decode[$mem[$pc++]]->();
                }
            } else {
                while ($ic-- > 0) {
                    $decode[$mem[$pc++]]->();
                }
            }
        },

        load_rom => sub {
            my ($f, $a) = @_;
            open my $fh, '<', $f or croak "Can't read $f ($!)\n";
            binmode $fh;
            my $sz = -s $fh;
            sysread $fh, my $buf, $sz
                or croak "Error reading $f ($!)\n";
            $self->write_chunk($a, $buf);
        },

        poke_code => sub {
            my $addr = shift;
            $mem[$addr++] = $_ for @_;
        },

        make_vector => sub {
            my ($call, $vec, $func) = @_;
            $mem[$call + 0] = 0x6C;                 # JMP (indirect)
            $mem[$call + 1] = $vec & 0xFF;
            $mem[$call + 2] = ($vec >> 8) & 0xFF;

            my $addr = $jumptab;
            $mem[$jumptab++] = ESCAPE_OP;
            $mem[$jumptab++] = ESCAPE_SIG;
            $mem[$jumptab++] = $func;
            $mem[$jumptab++] = 0x60;

            $mem[$vec + 0] = $addr & 0xFF;
            $mem[$vec + 1] = ($addr >> 8) & 0xFF;
        },

        get_state => sub {
            return ($a, $x, $y, $s, $p, $pc);
        },

        get_xy => sub {
            return $x || ($y << 8);
        },

        set_xy => sub {
            my $v = shift;
            $x = $v & 0xFF;
            $y = ($v >> 8) & 0xFF;
        },
        
        decode_flags => sub {
            my $f = shift;
            my $b = 0x80;
            my $n = FLAGS;
            my $desc = '';
            while ($n) {
                $desc .= ($f & $b) ? substr($n, 0, 1) : '-';
                $n = substr($n, 1);
                $b >>= 1;
            }
            return $desc;
        }
    };

    # Generate register accessors.
    for my $reg (qw(a x y s p pc)) {
        $cpu{$id}->{"get_$reg"} = eval "sub { return \$$reg; }";
        $cpu{$id}->{"set_$reg"} = eval "sub { \$$reg = \$_[0]; }";
    }
}

sub AUTOMETHOD {
    my ($self, $id, @args) = @_;
    my $methname = $_;

    if (exists($cpu{$id}->{$methname})) {
        return sub {
            return $cpu{$id}->{$methname}->(@args);
        }
    }

    return;
}

sub call_os {
    my $self = shift;
    my $id   = ident($self);
    croak "call_os() not supported";
}

# Functions that generate code fragments
sub _push {
    my $r = '';
    for (@_) {
        $r .=
              '$mem[STACK + $s] = (' . $_
            . ') & 0xFF; $s = ($s - 1) & 0xFF;' . "\n";
    }
    return $r;
}

sub _pop {
    my $r = '';
    for (@_) {
        $r .=
              '$s = ($s + 1) & 0xFF; ' . $_
            . ' = $mem[STACK + $s];' . "\n";
    }
    return $r;
}

sub _pop_p {
    return '$s = ($s + 1) & 0xFF; $p = $mem[STACK + $s] | R | B;'
        . "\n";
}

# Addressing modes return a list containing setup code, lvalue
sub _zpix {
    return (
        'my $ea = $mem[$pc++] + $x; '
            . '$ea = $mem[$ea & 0xFF] | ($mem[($ea + 1) & 0xFF] << 8)'
            . ";\n",
        '$mem[$ea]'
    );
}

sub _zpi {
    return (
        'my $ea = $mem[$pc++]; '
            . '$ea = $mem[$ea & 0xFF] | ($mem[($ea + 1) & 0xFF] << 8)'
            . ";\n",
        '$mem[$ea]'
    );
}

sub _zpiy {
    return (
        'my $ea = $mem[$pc++]; '
            . '$ea = ($mem[$ea & 0xFF] | ($mem[($ea + 1) & 0xFF] << 8)) + $y'
            . ";\n",
        '$mem[$ea]'
    );
}

sub _zp {
    return ('my $ea = $mem[$pc++];' . "\n", '$mem[$ea]');
}

sub _zpx {
    return ('my $ea = ($mem[$pc++] + $x) & 0xFF;' . "\n", '$mem[$ea]');
}

sub _zpy {
    return ('my $ea = ($mem[$pc++] + $y) & 0xFF;' . "\n", '$mem[$ea]');
}

sub _abs {
    return ('my $ea = $mem[$pc] | ($mem[$pc+1] << 8); $pc += 2;' . "\n",
        '$mem[$ea]');
}

sub _absx {
    return (
        'my $ea = ($mem[$pc] | ($mem[$pc+1] << 8)) + $x; $pc += 2;'
            . "\n",
        '$mem[$ea]'
    );
}

sub _absy {
    return (
        'my $ea = ($mem[$pc] | ($mem[$pc+1] << 8)) + $y; $pc += 2;'
            . "\n",
        '$mem[$ea]'
    );
}

sub _imm {
    return ('my $v = $mem[$pc++];' . "\n", '$v');
}

sub _acc {
    return ('', '$a');
}

sub _rel {
    # Doesn't return an lvalue
    return ('my $t = $mem[$pc++];' . "\n",
        '($pc + $t - (($t & 0x80) ? 0x100 : 0))');
}

sub _status {
    my $reg = shift || '$a';
    return '$p = ($p & ~(N | Z) | $zn[' . $reg . ']);' . "\n";
}

sub _ora {
    return $_[0] . '$a |= ' . $_[1] . ";\n" . _status();
}

sub _and {
    return $_[0] . '$a &= ' . $_[1] . ";\n" . _status();
}

sub _eor {
    return $_[0] . '$a ^= ' . $_[1] . ";\n" . _status();
}

sub _bit {
    return $_[0]
        . '$p = ($p & ~(N|V)) | ('
        . $_[1]
        . ' & (N|V));' . "\n"
        . 'if (($a & '
        . $_[1]
        . ') == 0) { $p |= Z; } else { $p &= ~Z; }' . "\n";
}

sub _asl {
    return $_[0]
        . 'my $w = ('
        . $_[1]
        . ') << 1; ' . "\n"
        . 'if ($w & 0x100) { $p |= C; $w &= ~0x100; } else { $p &= ~C; }'
        . "\n"
        . _status('$w')
        . $_[1]
        . ' = $w;' . "\n";
}

sub _lsr {
    return $_[0]
        . 'my $w = '
        . $_[1] . ";\n"
        . 'if (($w & 1) != 0) { $p |= C; } else { $p &= ~C; }' . "\n"
        . '$w >>= 1;' . "\n"
        . _status('$w')
        . $_[1]
        . ' = $w;' . "\n";
}

sub _rol {
    return $_[0]
        . 'my $w = ('
        . $_[1]
        . ' << 1) | ($p & C);' . "\n"
        . 'if ($w >= 0x100) { $p |= C; $w -= 0x100; } else { $p &= ~C; };'
        . "\n"
        . _status('$w')
        . $_[1]
        . ' = $w;' . "\n";
}

sub _ror {
    return $_[0]
        . 'my $w = '
        . $_[1]
        . ' | (($p & C) << 8);' . "\n"
        . 'if (($w & 1) != 0) { $p |= C; } else { $p &= ~C; }' . "\n"
        . '$w >>= 1;' . "\n"
        . _status('$w')
        . $_[1]
        . ' = $w;' . "\n";
}

sub _sto {
    return $_[0] . "$_[1] = $_[2];\n";
}

sub _lod {
    return $_[0] . "$_[2] = $_[1];\n" . _status($_[2]);
}

sub _cmp {
    return $_[0]
        . 'my $w = '
        . $_[2] . ' - '
        . $_[1] . ";\n"
        . 'if ($w < 0) { $w += 0x100; $p &= ~C; } else { $p |= C; }'
        . "\n"
        . _status('$w');
}

sub _tsb {
    return 'croak "TSB not supported\n";' . "\n";
}

sub _trb {
    return 'croak "TRB not supported\n";' . "\n";
}

sub _inc {
    return $_[0]
        . $_[1] . ' = ('
        . $_[1]
        . ' + 1) & 0xFF;' . "\n"
        . _status($_[1]);
}

sub _dec {
    return $_[0]
        . $_[1] . ' = ('
        . $_[1]
        . ' + 0xFF) & 0xFF;' . "\n"
        . _status($_[1]);
}

sub _adc {
    return $_[0]
        . 'my $w = '
        . $_[1] . ";\n"
        . 'if ($p & D) {' . "\n"
        . 'my $lo = ($a & 0x0F) + ($w & 0x0F) + ($p & C);' . "\n"
        . 'if ($lo > 9) { $lo += 6; }' . "\n"
        . 'my $hi = ($a >> 4) + ( $w >> 4) + ($lo > 15 ? 1 : 0);' . "\n"
        . '$a = ($lo & 0x0F) | ($hi << 4);' . "\n"
        . '$p = ($p & ~C) | ($hi > 15 ? C : 0);' . "\n"
        . '} else {' . "\n"
        . 'my $lo = $a + $w + ($p & C);' . "\n"
        . '$p &= ~(N | V | Z | C);' . "\n"
        . '$p |= (~($a ^ $w) & ($a ^ $lo) & 0x80 ? V : 0) | ($lo & 0x100 ? C : 0);'
        . "\n"
        . '$a = $lo & 0xFF;' . "\n"
        . _status() . '}' . "\n";
}

sub _sbc {
    return $_[0]
        . 'my $w = '
        . $_[1] . ";\n"
        . 'if ($p & D) {' . "\n"
        . 'my $lo = ($a & 0x0F) - ($w & 0x0F) - (~$p & C);' . "\n"
        . 'if ($lo & 0x10) { $lo -= 6; }' . "\n"
        . 'my $hi = ($a >> 4) - ($w >> 4) - (($lo & 0x10) >> 4);' . "\n"
        . 'if ($hi & 0x10) { $hi -= 6; }' . "\n"
        . '$a = ($lo & 0x0F) | ($hi << 4);' . "\n"
        . '$p = ($p & ~C) | ($hi > 15 ? 0 : C);' . "\n"
        . '} else {' . "\n"
        . 'my $lo = $a - $w - (~$p & C);' . "\n"
        . '$p &= ~(N | V | Z | C);' . "\n"
        . '$p |= (($a ^ $w) & ($a ^ $lo) & 0x80 ? V : 0) | ($lo & 0x100 ? 0 : C);'
        . "\n"
        . '$a = $lo & 0xFF;' . "\n"
        . _status() . '}' . "\n";
}

sub _bra {
    return $_[0] . '$pc = ' . $_[1] . ";\n";
}

sub _bfz {
    return $_[0]
        . 'if (($p & '
        . $_[2]
        . ') == 0) { $pc = '
        . $_[1] . '; }' . "\n";
}

sub _bfnz {
    return $_[0]
        . 'if (($p & '
        . $_[2]
        . ') != 0) { $pc = '
        . $_[1] . '; }' . "\n";
}

sub _jmp_i {
    my $a = shift;
    return '$pc = $mem[' . $a
        . '] | ($mem['
        . $a
        . ' + 1] << 8);' . "\n";
}

sub _jmp {
    return _jmp_i('$pc');
}

sub _jmpi {
    return 'my $w = $mem[$pc] | ($mem[$pc + 1] << 8); ' . _jmp_i('$w');
}

sub _jmpix {
    return 'my $w = ($mem[$pc] | ($mem[$pc + 1] << 8)) + $x; '
        . _jmp_i('$w');
}

sub _rts {
    return 'my ($lo, $hi); '
        . _pop('$lo')
        . _pop('$hi')
        . '$pc = ($lo | ($hi << 8)) + 1;' . "\n";
}

1;
__END__

=head1 NAME

Acme::6502 - Pure Perl 65C02 simulator.

=head1 VERSION

This document describes Acme::6502 version 0.0.6

=head1 SYNOPSIS

    use Acme::6502;
    
    my $cpu = Acme::6502->new();
    
    # Set start address
    $cpu->set_pc(0x8000);
    
    # Load ROM image
    $cpu->load_rom('myrom.rom', 0x8000);
    
    # Run for 1,000,000 instructions then return
    $cpu->run(1_000_000);
  
=head1 DESCRIPTION

Imagine the nightmare scenario: your boss tells you about a legacy
system you have to support. How bad could it be? COBOL? Fortran? Worse:
it's an embedded 6502 system run by a family of squirrels (see Dilberts
passim). Fortunately there's a pure Perl 6502 emulator that works so
well the squirrels will never know the difference.

=head1 INTERFACE 

=over

=item C<call_os( $vec_number )>

Subclass to provide OS entry points. OS vectors are installed by calling
C<make_vector>. When the vector is called C<call_os()> will be called
with the vector number.

=item C<get_a()>

Read the current value of the processor A register (accumulator).

=item C<get_p()>

Read the current value of the processor status register.

=item C<get_pc()>

Read the current value of the program counter.

=item C<get_s()>

Read the current value of the stack pointer.

=item C<get_x()>

Read the current value of the processor X index register.

=item C<get_y()>

Read the current value of the processor X index register.

=item C<get_xy()>

Read the value of X and Y as a sixteen bit number. X forms the lower 8
bits of the value and Y forms the upper 8 bits.

=item C<get_state()>

Returns an array containing the values of the A, X, Y, S, P and SP.

=item C<set_a( $value )>

Set the value of the processor A register (accumulator).

=item C<set_p( $value )>

Set the value of the processor status register.

=item C<set_pc( $value )>

Set the value of the program counter.

=item C<set_s( $value )>

Set the value of the stack pointer.

=item C<set_x( $value )>

Set the value of the X index register.

=item C<set_y( $value )>

Set the value of the Y index register.

=item C<set_xy( $value )>

Set the value of the X and Y registers to the specified sixteen bit
number. X gets the lower 8 bits, Y gets the upper 8 bits.

=item C<set_jumptab( $addr )>

Set the address of the block of memory that will be used to hold the
thunk blocks that correspond with vectored OS entry points. Each thunk
takes four bytes.

=item C<load_rom( $filename, $addr )>

Load a ROM image at the specified address.

=item C<make_vector( $jmp_addr, $vec_addr, $vec_number )>

Make a vectored entry point for an emulated OS. C<$jmp_addr> is the
address where an indirect JMP instruction (6C) will be placed,
C<$vec_addr> is the address of the vector and C<$vec_number> will be
passed to C<call_os> when the OS call is made.

=item C<poke_code( $addr, @bytes )>

Poke code directly at the specified address.

=item C<read_8( $addr )>

Read a byte at the specified address.

=item C<read_16( $addr )>

Read a sixteen bit (low, high) word at the specified address.

=item C<read_32( $addr )>

Read a 32 bit word at the specified address.

=item C<read_chunk( $start, $end )>

Read a chunk of data from C<$start> to C<$end> - 1 into a string.

=item C<read_str( $addr )>

Read a carriage return terminated (0x0D) string from the
specified address.

=item C<run( $count [, $callback ] )>

Execute the specified number of instructions and return. Optionally a
callback may be provided in which case it will be called before each
instruction is executed:

    my $cb = sub {
        my ($pc, $inst, $a, $x, $y, $s, $p) = @_;
        # Maybe output trace info
    }
    
    $cpu->run(100, $cb);

=item C<write_8( $addr, $value )>

Write the byte at the specified address.

=item C<write_16( $addr, $value )>

Write a sixteen bit (low, high) value at the specified address.

=item C<write_32( $addr, $value )>

Write a 32 bit value at the specified address.

=item C<write_chunk( $addr, $string )>

Write a chunk of data to memory.

=back

=head1 DIAGNOSTICS

=over

=item C<< Bad instruction at %s (%s) >>

The emulator hit an illegal 6502 instruction.

=back

=head1 CONFIGURATION AND ENVIRONMENT

Acme::6502 requires no configuration files or environment variables.

=head1 DEPENDENCIES

C<Acme::6502> needs C<Class::Std>.

=head1 INCOMPATIBILITIES

None reported.

=head1 BUGS AND LIMITATIONS

Doesn't have support for hardware emulation hooks - so memory mapped I/O
is out of the question until someone fixes it.

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
