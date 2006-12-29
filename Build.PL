use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Acme::6502',
    sign                => 1,
    license             => 'perl',
    dist_author         => 'Andy Armstrong <andy@hexten.net>',
    dist_version_from   => 'lib/Acme/6502.pm',
    requires => {
        'Test::More'        => 0,
        'version'           => 0,
        'Class::Std'        => 0,
        'Class::Std::Slots' => 0,
        'Term::ReadKey'     => 0,
    },
    add_to_cleanup      => [ 'Acme-6502-*' ],
);

$builder->create_build_script();
