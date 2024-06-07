require "oauth2"
require "omniauth"
require "securerandom"
require "socket"       # for SocketError
require "timeout"      # for Timeout::Error

module OmniAuth
  module Strategies
    # Authentication strategy for connecting with APIs constructed using
    # the [OAuth 2.0 Specification](http://tools.ietf.org/html/draft-ietf-oauth-v2-10).
    # You must generally register your application with the provider and
    # utilize an application id and secret in order to authenticate using
    # OAuth 2.0.
    class Shopify

      include OmniAuth::Strategy

      def self.inherited(subclass)
        OmniAuth::Strategy.included(subclass)
      end

      # An error that is indicated in the OAuth 2.0 callback.
      # This could be a `redirect_uri_mismatch` or other
      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason = nil, error_uri = nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(" | ")
        end
      end

      # Available scopes: content themes products customers orders script_tags shipping
      # read_*  or write_*
      DEFAULT_SCOPE = 'read_products'
      SCOPE_DELIMITER = ','
      MINUTE = 60
      CODE_EXPIRES_AFTER = 10 * MINUTE

      args %i[client_id client_secret]

      option :client_id, nil
      option :client_secret, nil
      option :client_options, {}
      option :authorize_params, {}
      option :authorize_options, %i[scope state]
      option :token_params, {}
      option :token_options, []
      option :auth_token_params, {}
      option :provider_ignores_state, false
      option :pkce, false
      option :pkce_verifier, nil
      option :pkce_options, {
        :code_challenge => proc { |verifier|
          Base64.urlsafe_encode64(
            Digest::SHA2.digest(verifier),
            :padding => false,
          )
        },
        :code_challenge_method => "S256",
      }

      attr_accessor :access_token

      option :client_options, {
        :authorize_url => '/admin/oauth/authorize',
        :token_url => '/admin/oauth/access_token'
      }

      option :callback_url
      option :myshopify_domain, 'myshopify.com'
      option :old_client_secret

      # When `true`, the user's permission level will apply (in addition to
      # the requested access scope) when making API requests to Shopify.
      option :per_user_permissions, false

      option :setup, proc { |env|
        strategy = env['omniauth.strategy']

        shopify_auth_params = strategy.session['shopify.omniauth_params'] ||
          strategy.session['omniauth.params'] ||
          strategy.request.params

        shopify_auth_params = shopify_auth_params && shopify_auth_params.with_indifferent_access
        shop = if shopify_auth_params && shopify_auth_params['shop']
          "https://#{shopify_auth_params['shop']}"
        else
          ''
        end

        strategy.options[:client_options][:site] = shop
      }

      uid { URI.parse(options[:client_options][:site]).host }

      extra do
        if access_token
          {
            'associated_user' => access_token['associated_user'],
            'associated_user_scope' => access_token['associated_user_scope'],
            'scope' => access_token['scope'],
            'session' => access_token['session']
          }
        end
      end

      def client
        ::OAuth2::Client.new(options.client_id, options.client_secret, deep_symbolize(options.client_options))
      end

      credentials do
        hash = {"token" => access_token.token}
        hash["refresh_token"] = access_token.refresh_token if access_token.expires? && access_token.refresh_token
        hash["expires_at"] = access_token.expires_at if access_token.expires?
        hash["expires"] = access_token.expires?
        hash
      end

      def token_params
        options.token_params.merge(options_for("token")).merge(pkce_token_params)
      end

      def valid_site?
        !!(/\A(https|http)\:\/\/[a-zA-Z0-9][a-zA-Z0-9\-]*\.#{Regexp.quote(options[:myshopify_domain])}[\/]?\z/ =~ options[:client_options][:site])
      end

      def valid_signature?
        return false unless request.POST.empty?

        params = request.GET
        signature = params['hmac']
        timestamp = params['timestamp']
        return false unless signature && timestamp

        return false unless timestamp.to_i > Time.now.to_i - CODE_EXPIRES_AFTER

        new_secret = options.client_secret
        old_secret = options.old_client_secret

        validate_signature(new_secret) || (old_secret && validate_signature(old_secret))
      end

      def normalized_scopes(scopes)
        scope_list = scopes.to_s.split(SCOPE_DELIMITER).map(&:strip).reject(&:empty?).uniq
        ignore_scopes = scope_list.map { |scope| scope =~ /\A(unauthenticated_)?write_(.*)\z/ && "#{$1}read_#{$2}" }.compact
        scope_list - ignore_scopes
      end

      def self.encoded_params_for_signature(params)
        params = params.dup
        params.delete('hmac')
        params.delete('signature') # deprecated signature
        Rack::Utils.build_query(params.sort)
      end

      def self.hmac_sign(encoded_params, secret)
        OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, secret, encoded_params)
      end

      def valid_permissions?(token)
        return false unless token

        return true if options[:per_user_permissions] && token['associated_user']
        return true if !options[:per_user_permissions] && !token['associated_user']

        false
      end

      def fix_https
        options[:client_options][:site] = options[:client_options][:site].gsub(/\Ahttp\:/, 'https:')
      end

      def setup_phase
        super
        fix_https
      end

      def request_phase
        if valid_site?
          redirect client.auth_code.authorize_url({:redirect_uri => callback_url}.merge(authorize_params))
        else
          fail!(:invalid_site)
        end
      end

      def callback_phase
        return fail!(:invalid_site, CallbackError.new(:invalid_site, "OAuth endpoint is not a myshopify site.")) unless valid_site?
        return fail!(:invalid_signature, CallbackError.new(:invalid_signature, "Signature does not match, it may have been tampered with.")) unless valid_signature?

        token = build_access_token
        unless valid_permissions?(token)
          return fail!(:invalid_permissions, CallbackError.new(:invalid_permissions, "Requested API access mode does not match."))
        end

        error = request.params["error_reason"] || request.params["error"]
        if !options.provider_ignores_state && (request.params["state"].to_s.empty? || request.params["state"] != session.delete("omniauth.state"))
          fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
        elsif error
          fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
        else
          self.access_token = build_access_token
          self.access_token = access_token.refresh! if access_token.expired?
          super
        end
      rescue ::OAuth2::Error, CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def build_access_token
        @built_access_token ||= super
      end

      def authorize_params
        options.authorize_params[:state] = SecureRandom.hex(24)

        if OmniAuth.config.test_mode
          @env ||= {}
          @env["rack.session"] ||= {}
        end

        params = options.authorize_params
                        .merge(options_for("authorize"))
                        .merge(pkce_authorize_params)

        session["omniauth.pkce.verifier"] = options.pkce_verifier if options.pkce
        session["omniauth.state"] = params[:state]

        params[:scope] = normalized_scopes(params[:scope] || DEFAULT_SCOPE).join(SCOPE_DELIMITER)
        params[:grant_options] = ['per-user'] if options[:per_user_permissions]

        params
      end

      def callback_url
        options[:callback_url] || full_host + script_name + callback_path
      end

      private

      def validate_signature(secret)
        params = request.GET
        calculated_signature = self.class.hmac_sign(self.class.encoded_params_for_signature(params), secret)
        Rack::Utils.secure_compare(calculated_signature, params['hmac'])
      end

      def pkce_authorize_params
        return {} unless options.pkce

        options.pkce_verifier = SecureRandom.hex(64)

        # NOTE: see https://tools.ietf.org/html/rfc7636#appendix-A
        {
          :code_challenge => options.pkce_options[:code_challenge]
                                    .call(options.pkce_verifier),
          :code_challenge_method => options.pkce_options[:code_challenge_method],
        }
      end

      def pkce_token_params
        return {} unless options.pkce

        {:code_verifier => session.delete("omniauth.pkce.verifier")}
      end

      def build_access_token
        verifier = request.params["code"]
        client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end

      def deep_symbolize(options)
        options.each_with_object({}) do |(key, value), hash|
          hash[key.to_sym] = value.is_a?(Hash) ? deep_symbolize(value) : value
        end
      end

      def options_for(option)
        hash = {}
        options.send(:"#{option}_options").select { |key| options[key] }.each do |key|
          hash[key.to_sym] = if options[key].respond_to?(:call)
                              options[key].call(env)
                            else
                              options[key]
                            end
        end
        hash
      end

    end
  end
end
