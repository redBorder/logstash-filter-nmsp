# -*- encoding: utf-8 -*-
# stub: minitar 0.5.4 ruby lib

Gem::Specification.new do |s|
  s.name = "minitar".freeze
  s.version = "0.5.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Austin Ziegler, Mauricio Fernandez, Antoine Toulme".freeze]
  s.autorequire = "archive/tar/minitar".freeze
  s.date = "2012-11-14"
  s.description = "Archive::Tar::Minitar is a pure-Ruby library and command-line utility that provides the ability to deal with POSIX tar(1) archive files. The implementation is based heavily on Mauricio Ferna'ndez's implementation in rpa-base, but has been reorganised to promote reuse in other projects. Antoine Toulme forked the original project on rubyforge to place it on github, under http://www.github.com/atoulme/minitar".freeze
  s.email = "antoine@lunar-ocean.com".freeze
  s.executables = ["minitar".freeze]
  s.extra_rdoc_files = ["README".freeze, "ChangeLog".freeze, "Install".freeze]
  s.files = ["ChangeLog".freeze, "Install".freeze, "README".freeze, "bin/minitar".freeze]
  s.homepage = "http://www.github.com/atoulme/minitar".freeze
  s.rdoc_options = ["--title".freeze, "Archive::Tar::MiniTar -- A POSIX tarchive library".freeze, "--main".freeze, "README".freeze, "--line-numbers".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.2".freeze)
  s.rubygems_version = "2.7.6".freeze
  s.summary = "Provides POSIX tarchive management from Ruby programs.".freeze

  s.installed_by_version = "2.7.6" if s.respond_to? :installed_by_version
end
