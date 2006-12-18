use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Acme::6502',
    AUTHOR              => 'Andy Armstrong <andy@hexten.net>',
    VERSION_FROM        => 'lib/Acme/6502.pm',
    ABSTRACT_FROM       => 'lib/Acme/6502.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'version'    => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Acme-6502-*' },
);
