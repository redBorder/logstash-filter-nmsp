# -*- encoding: utf-8 -*-
# stub: ruby-maven 3.3.12 ruby lib

Gem::Specification.new do |s|
  s.name = "ruby-maven".freeze
  s.version = "3.3.12"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Christian Meier".freeze]
  s.date = "2016-06-14"
  s.description = "maven support for ruby DSL pom files. MRI needs java/javac installed.".freeze
  s.email = ["m.kristian@web.de".freeze]
  s.executables = ["rmvn".freeze]
  s.files = ["bin/rmvn".freeze]
  s.homepage = "https://github.com/takari/ruby-maven".freeze
  s.licenses = ["EPL".freeze]
  s.rdoc_options = ["--main".freeze, "README.md".freeze]
  s.rubygems_version = "2.7.6".freeze
  s.summary = "maven support for ruby projects".freeze

  s.installed_by_version = "2.7.6" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<ruby-maven-libs>.freeze, ["~> 3.3.9"])
      s.add_development_dependency(%q<minitest>.freeze, ["~> 5.3"])
      s.add_development_dependency(%q<rake>.freeze, ["~> 10.3"])
    else
      s.add_dependency(%q<ruby-maven-libs>.freeze, ["~> 3.3.9"])
      s.add_dependency(%q<minitest>.freeze, ["~> 5.3"])
      s.add_dependency(%q<rake>.freeze, ["~> 10.3"])
    end
  else
    s.add_dependency(%q<ruby-maven-libs>.freeze, ["~> 3.3.9"])
    s.add_dependency(%q<minitest>.freeze, ["~> 5.3"])
    s.add_dependency(%q<rake>.freeze, ["~> 10.3"])
  end
end
