$: << File.expand_path("../../lib", __FILE__)
require 'bundler/setup'
require 'omniauth-shopify-app'

require 'minitest/autorun'
require 'minitest/focus'
require 'rack/session'
require 'fakeweb'
require 'json'
require 'active_support/core_ext/hash'
require 'byebug'

OmniAuth.config.logger = Logger.new(nil)
OmniAuth.config.allowed_request_methods = [:post, :get]

FakeWeb.allow_net_connect = false
