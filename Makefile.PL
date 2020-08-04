#!/usr/bin/perl
use 5.008;
use ExtUtils::MakeMaker;
WriteMakefile(
	NAME => 'DJabberd::Plugin::XDisco',
	VERSION_FROM => 'lib/DJabberd/Plugin/XDisco.pm',
	ABSTRACT_FROM => 'lib/DJabberd/Plugin/XDisco.pm',
	PREREQ_PM => {
		'DJabberd' => '0.86',
	},
	AUTHOR => 'Ruslan N. Marchenko <me@ruff.mobi>',
);
