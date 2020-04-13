# -*- encoding: utf-8 -*-
# stub: logstash-core 5.6.4 java lib

Gem::Specification.new do |s|
  s.name = "logstash-core".freeze
  s.version = "5.6.4"
  s.platform = "java".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Elastic".freeze]
  s.date = "2017-10-31"
  s.description = "The core components of logstash, the scalable log and event management tool".freeze
  s.email = ["info@elastic.co".freeze]
  s.homepage = "http://www.elastic.co/guide/en/logstash/current/index.html".freeze
  s.licenses = ["Apache License (2.0)".freeze]
  s.requirements = ["jar org.apache.logging.log4j:log4j-slf4j-impl, 2.6.2".freeze, "jar org.apache.logging.log4j:log4j-api, 2.6.2".freeze, "jar org.apache.logging.log4j:log4j-core, 2.6.2".freeze, "jar com.fasterxml.jackson.core:jackson-core, 2.9.1".freeze, "jar com.fasterxml.jackson.core:jackson-databind, 2.9.1".freeze, "jar com.fasterxml.jackson.core:jackson-annotations, 2.9.1".freeze, "jar com.fasterxml.jackson.module:jackson-module-afterburner, 2.9.1".freeze, "jar com.fasterxml.jackson.dataformat:jackson-dataformat-cbor, 2.9.1".freeze]
  s.rubygems_version = "2.7.6".freeze
  s.summary = "logstash-core - The core components of logstash".freeze

  s.installed_by_version = "2.7.6" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<pry>.freeze, ["~> 0.10.1"])
      s.add_runtime_dependency(%q<stud>.freeze, ["~> 0.0.19"])
      s.add_runtime_dependency(%q<clamp>.freeze, ["~> 0.6.5"])
      s.add_runtime_dependency(%q<filesize>.freeze, ["= 0.0.4"])
      s.add_runtime_dependency(%q<gems>.freeze, ["~> 0.8.3"])
      s.add_runtime_dependency(%q<concurrent-ruby>.freeze, [">= 1.0.5", "~> 1.0"])
      s.add_runtime_dependency(%q<rack>.freeze, ["= 1.6.6"])
      s.add_runtime_dependency(%q<sinatra>.freeze, [">= 1.4.6", "~> 1.4"])
      s.add_runtime_dependency(%q<puma>.freeze, ["~> 2.16"])
      s.add_runtime_dependency(%q<jruby-openssl>.freeze, ["= 0.9.19"])
      s.add_runtime_dependency(%q<chronic_duration>.freeze, ["= 0.10.6"])
      s.add_runtime_dependency(%q<treetop>.freeze, ["< 1.5.0"])
      s.add_runtime_dependency(%q<i18n>.freeze, ["= 0.6.9"])
      s.add_runtime_dependency(%q<minitar>.freeze, ["~> 0.5.4"])
      s.add_runtime_dependency(%q<rubyzip>.freeze, ["~> 1.1.7"])
      s.add_runtime_dependency(%q<thread_safe>.freeze, ["~> 0.3.5"])
      s.add_runtime_dependency(%q<jrjackson>.freeze, ["~> 0.4.3"])
      s.add_runtime_dependency(%q<jar-dependencies>.freeze, [">= 0"])
      s.add_runtime_dependency(%q<ruby-maven>.freeze, ["~> 3.3.9"])
      s.add_runtime_dependency(%q<elasticsearch>.freeze, [">= 5.0.4", "~> 5.0"])
      s.add_runtime_dependency(%q<manticore>.freeze, ["< 1.0.0", ">= 0.5.4"])
    else
      s.add_dependency(%q<pry>.freeze, ["~> 0.10.1"])
      s.add_dependency(%q<stud>.freeze, ["~> 0.0.19"])
      s.add_dependency(%q<clamp>.freeze, ["~> 0.6.5"])
      s.add_dependency(%q<filesize>.freeze, ["= 0.0.4"])
      s.add_dependency(%q<gems>.freeze, ["~> 0.8.3"])
      s.add_dependency(%q<concurrent-ruby>.freeze, [">= 1.0.5", "~> 1.0"])
      s.add_dependency(%q<rack>.freeze, ["= 1.6.6"])
      s.add_dependency(%q<sinatra>.freeze, [">= 1.4.6", "~> 1.4"])
      s.add_dependency(%q<puma>.freeze, ["~> 2.16"])
      s.add_dependency(%q<jruby-openssl>.freeze, ["= 0.9.19"])
      s.add_dependency(%q<chronic_duration>.freeze, ["= 0.10.6"])
      s.add_dependency(%q<treetop>.freeze, ["< 1.5.0"])
      s.add_dependency(%q<i18n>.freeze, ["= 0.6.9"])
      s.add_dependency(%q<minitar>.freeze, ["~> 0.5.4"])
      s.add_dependency(%q<rubyzip>.freeze, ["~> 1.1.7"])
      s.add_dependency(%q<thread_safe>.freeze, ["~> 0.3.5"])
      s.add_dependency(%q<jrjackson>.freeze, ["~> 0.4.3"])
      s.add_dependency(%q<jar-dependencies>.freeze, [">= 0"])
      s.add_dependency(%q<ruby-maven>.freeze, ["~> 3.3.9"])
      s.add_dependency(%q<elasticsearch>.freeze, [">= 5.0.4", "~> 5.0"])
      s.add_dependency(%q<manticore>.freeze, ["< 1.0.0", ">= 0.5.4"])
    end
  else
    s.add_dependency(%q<pry>.freeze, ["~> 0.10.1"])
    s.add_dependency(%q<stud>.freeze, ["~> 0.0.19"])
    s.add_dependency(%q<clamp>.freeze, ["~> 0.6.5"])
    s.add_dependency(%q<filesize>.freeze, ["= 0.0.4"])
    s.add_dependency(%q<gems>.freeze, ["~> 0.8.3"])
    s.add_dependency(%q<concurrent-ruby>.freeze, [">= 1.0.5", "~> 1.0"])
    s.add_dependency(%q<rack>.freeze, ["= 1.6.6"])
    s.add_dependency(%q<sinatra>.freeze, [">= 1.4.6", "~> 1.4"])
    s.add_dependency(%q<puma>.freeze, ["~> 2.16"])
    s.add_dependency(%q<jruby-openssl>.freeze, ["= 0.9.19"])
    s.add_dependency(%q<chronic_duration>.freeze, ["= 0.10.6"])
    s.add_dependency(%q<treetop>.freeze, ["< 1.5.0"])
    s.add_dependency(%q<i18n>.freeze, ["= 0.6.9"])
    s.add_dependency(%q<minitar>.freeze, ["~> 0.5.4"])
    s.add_dependency(%q<rubyzip>.freeze, ["~> 1.1.7"])
    s.add_dependency(%q<thread_safe>.freeze, ["~> 0.3.5"])
    s.add_dependency(%q<jrjackson>.freeze, ["~> 0.4.3"])
    s.add_dependency(%q<jar-dependencies>.freeze, [">= 0"])
    s.add_dependency(%q<ruby-maven>.freeze, ["~> 3.3.9"])
    s.add_dependency(%q<elasticsearch>.freeze, [">= 5.0.4", "~> 5.0"])
    s.add_dependency(%q<manticore>.freeze, ["< 1.0.0", ">= 0.5.4"])
  end
end
