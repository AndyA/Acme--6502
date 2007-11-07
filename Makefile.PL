use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    ( MM->can( 'signature_target' ) ? ( SIGN => 1 ) : () ),
    NAME          => 'Acme::6502',
    AUTHOR        => 'Andy Armstrong <andy@hexten.net>',
    VERSION_FROM  => 'lib/Acme/6502.pm',
    ABSTRACT_FROM => 'lib/Acme/6502.pm',
    LICENSE       => 'perl',
    PL_FILES      => {},
    PREREQ_PM     => {
        'Test::More'        => 0,
        'Class::Std'        => 0,
        'Class::Std::Slots' => 0,
        'Term::ReadKey'     => 0,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES    => 'Acme-6502-*' },
);
