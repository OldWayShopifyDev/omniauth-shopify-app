# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'omniauth/shopify/version'

Gem::Specification.new do |s|
  s.name     = 'omniauth-shopify-app'
  s.version  = OmniAuth::Shopify::VERSION
  s.authors  = ['Hopper Gee']
  s.email    = ['hopper.gee@hey.com']
  s.summary  = 'Shopify strategy for OmniAuth'
  s.homepage = 'https://github.com/OldWayShopifyDev/omniauth-shopify-app'
  s.license = 'MIT'

  s.metadata['allowed_push_host'] = 'https://rubygems.org'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']
  s.required_ruby_version = '>= 2.1.9'

  s.add_dependency "oauth2",     [">= 1.4", "< 3"]
  s.add_dependency "omniauth",   "~> 2.0"
  s.add_runtime_dependency 'activesupport'

  s.add_development_dependency 'minitest', '~> 5.6'
  s.add_development_dependency 'rspec', '~> 3.9.0'
  s.add_development_dependency 'fakeweb', '~> 1.3'
  s.add_development_dependency 'rack-session', '~> 2.0'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'minitest-focus'
end
