$:.unshift File.expand_path("../lib", __FILE__)
require "magistrate/version"

Gem::Specification.new do |gem|
  gem.name     = "magistrate-mckinsey"
  gem.version  = Magistrate::VERSION

  gem.author   = "Drew Blas, Jake Varghese"
  gem.email    = "drew.blas@gmail.com, jake_varghese@external.mckinsey.com"
  gem.homepage = "http://githuben.intranet.mckinsey.com/DigitalStrategy/magistrate"
  gem.summary  = "Cluster-based process / worker manager"

  gem.description = gem.summary

  gem.files = Dir["**/*"].select { |d| d =~ %r{^(README|bin/|lib/|spec/)} }
  #gem.files << "man/magistrate.1"

  gem.executables << 'magistrate'

  gem.add_runtime_dependency 'json'
  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'ronn'
  gem.add_development_dependency 'fakefs', '~> 0.2.1'
  gem.add_development_dependency 'rcov',   '~> 0.9.8'
  gem.add_development_dependency 'rr',     '~> 1.0.2'
  gem.add_development_dependency 'rspec',  '~> 2.6.0'
  gem.add_development_dependency 'ruby-debug'
  gem.add_development_dependency "webmock", "~> 1.6.4"
end