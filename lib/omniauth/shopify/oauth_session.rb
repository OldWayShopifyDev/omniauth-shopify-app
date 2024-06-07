require 'rack'
require_relative './encryptor'

# Copy and modify from https://github.com/cvonkleist/encrypted_cookie

module OmniAuth
  module Shopify
    class OAuthSession
      EXPIRES = '_encrypted_cookie_expires_'
      KEY = 'shopify_oauth_session'

      def initialize(app, options={})
        @app = app
        @key = options[:key] || KEY
        @secret = options[:secret]
        fail "Error! A secret is required to use encrypted cookies. Do something like this:\n\nuse OmniAuth::Shopify::OauthSession, :secret => YOUR_VERY_LONG_VERY_RANDOM_SECRET_KEY_HERE" unless @secret
        @default_options = {:domain => nil,
          :path => "/",
          :time_to_live => 1800,
          :expire_after => nil}.merge(options)
        @encryptor = Encryptor.new(@secret)
      end

      def call(env)
        load_session(env)
        status, headers, body = @app.call(env)
        commit_session(env, status, headers, body)
      end

      private

      def remove_expiration(session_data)
        expires = session_data.delete(EXPIRES)
        if expires and expires < Time.now
          session_data.clear
        end
      end

      def load_session(env)
        request = Rack::Request.new(env)
        env["rack.#{@key}.options"] = @default_options.dup

        session_data = request.cookies[@key]
        session_data = @encryptor.decrypt(session_data)
        session_data = Marshal.load(session_data)
        remove_expiration(session_data)

        env["rack.#{@key}"] = session_data
      rescue
        env["rack.#{@key}"] = Hash.new
      end

      def add_expiration(session_data, options)
        if options[:time_to_live] && !session_data.key?(EXPIRES)
          expires = Time.now + options[:time_to_live]
          session_data.merge!({EXPIRES => expires})
        end
      end

      def commit_session(env, status, headers, body)
        options = env["rack.#{@key}.options"]

        session_data = env["rack.#{@key}"]
        add_expiration(session_data, options)
        session_data = Marshal.dump(session_data)
        session_data = @encryptor.encrypt(session_data)

        if session_data.size > (4096 - @key.size)
          env["rack.errors"].puts("Warning! ShopifyOAuthSession data size exceeds 4K. Content dropped.")
        else
          cookie = Hash.new
          cookie[:value] = session_data
          cookie[:expires] = Time.now + options[:expire_after] unless options[:expire_after].nil?
          Rack::Utils.set_cookie_header!(headers, @key, cookie.merge(options))
        end

        [status, headers, body]
      end
    end
  end
end
