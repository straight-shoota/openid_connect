require "./spec_helper"
require "../src/provider"

describe OpenIDConnect::Provider do
  it ".new" do
    issuer = URI.parse("https://login.example.com")
    client = OAuth2::Client.new "login.example.com",
      client_id: "test-client", client_secret: "test-secret"
    public_key = "sesame"
    provider = OpenIDConnect::Provider.new issuer, client, public_key
    provider.issuer.should eq issuer
    provider.client_id.should eq "test-client"
    provider.client_secret.should eq "test-secret"
    provider.public_key.should eq "sesame"
  end

  describe "#authorize_uri" do
    it "default" do
      provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
        client_id: "test-client", client_secret: "test-secret",
        redirect_uri: "https://example.com/redirect"

      uri = provider.authorize_uri
      uri = URI.parse(uri)
      uri.scheme.should eq "https"
      uri.authority.should eq "login.example.com"
      uri.path.should eq "/oauth2/authorize"
      uri.query_params.should eq URI::Params{
        "client_id"     => "test-client",
        "redirect_uri"  => "https://example.com/redirect",
        "response_type" => "code",
        "scope"         => "openid",
      }
    end

    it "scope" do
      provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
        client_id: "test-client", client_secret: "test-secret",
        redirect_uri: "https://example.com/redirect"

      uri = provider.authorize_uri("openid offline_access")
      query = URI.parse(uri).query_params
      query["scope"].should eq "openid offline_access"

      uri = provider.authorize_uri("offline_access")
      query = URI.parse(uri).query_params
      query["scope"].should eq "offline_access"
    end

    it "state" do
      provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
        client_id: "test-client", client_secret: "test-secret",
        redirect_uri: "https://example.com/redirect"

      uri = provider.authorize_uri(state: "abcde")
      uri = URI.parse(uri)
      uri.scheme.should eq "https"
      uri.authority.should eq "login.example.com"
      uri.path.should eq "/oauth2/authorize"
      uri.query_params.should eq URI::Params{
        "client_id"     => "test-client",
        "redirect_uri"  => "https://example.com/redirect",
        "response_type" => "code",
        "scope"         => "openid",
        "state"         => "abcde",
      }
    end

    it "nonce" do
      provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
        client_id: "test-client", client_secret: "test-secret",
        redirect_uri: "https://example.com/redirect"

      uri = provider.authorize_uri(nonce: "12345")
      uri = URI.parse(uri)
      uri.scheme.should eq "https"
      uri.authority.should eq "login.example.com"
      uri.path.should eq "/oauth2/authorize"
      uri.query_params.should eq URI::Params{
        "client_id"     => "test-client",
        "redirect_uri"  => "https://example.com/redirect",
        "response_type" => "code",
        "scope"         => "openid",
        "nonce"         => "12345",
      }
    end

    it "custom fields" do
      provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
        client_id: "test-client", client_secret: "test-secret",
        redirect_uri: "https://example.com/redirect"

      uri = provider.authorize_uri(state: "abcde", nonce: "12345") do |form|
        form.add "custom_field", "custom_value"
      end
      uri = URI.parse(uri)
      uri.query_params.should eq URI::Params{
        "client_id"     => "test-client",
        "redirect_uri"  => "https://example.com/redirect",
        "response_type" => "code",
        "scope"         => "openid",
        "state"         => "abcde",
        "nonce"         => "12345",
        "custom_field"  => "custom_value",
      }
    end
  end

  private_key = <<-KEY
                -----BEGIN PRIVATE KEY-----
                MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALn7n7GdaCDE2eeY
                JI1sjBNAWNzJrBy+Y+6l5ezXSx+FQAdTG2ZPnMfcAjjomtFk3spXkBzltBbMX1kw
                94eqarkUF1iiggXxbuVW1jHbc5Bfm+MVE3QtFjyHI4ovTtSz5pR4zANdfszqjnxc
                7huo6HykY6oUuxwICR0A/2UOB4MbAgMBAAECgYBxG3+OdI1sSGvBdnzcaaRy3NJu
                TFRZEs0RyWEg/fpZDB/ZlIh4W3ic78eGNqhZKoB4DHK/sE8rAlYGl0oi/thx9u7Z
                zUnFaBpy6i17AyTkhg9dSzz1BjcAvkjgEl1mp3ej0rg5bBqS6SR+PEcoUL+CuJ81
                rjJVDohmf5e5b8CymQJBAOWbORRqnODSfS3eCYropAP1/lh1cpgZjNg7dJyu2vPn
                d97Cp8Nd0sLtMYv2rD28YQW9ITvbu/BHdf74NnpFZi8CQQDPXKpQ2es/DMbHcm4g
                0heB/MZOriBJ/7FGNvmoMlQ+cy3gjc+s/JWmbfhpQKCjbqCjb6K0EaPMUNokI5Pi
                LOLVAkAmroTqRJ/TXILMVGjlJxZiuHG2M2sv5rYMw898ihTHHIrcU4zx4/+a6Vz8
                iH0yFWd/EQLlU7qQ22ksoGKFLOXvAkEAmtHh67m4lXuRkmoSZXjWyluTKD2DqBw7
                HGSBZB4nnfTbBPR8YPi5NuiWduckyMEZOM1p2i3tcOfQ5viVOmIu/QJBAOQQKmlh
                Dg3R5x6CDXE9Wp/X18ej9YYca5JyN9Q9Mj+TQtomNgzbJx6GKea4seBjep0MmC0R
                u3hYblc1DOHJ9o0=
                -----END PRIVATE KEY-----
                KEY

  public_key = <<-KEY
               -----BEGIN PUBLIC KEY-----
               MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5+5+xnWggxNnnmCSNbIwTQFjc
               yawcvmPupeXs10sfhUAHUxtmT5zH3AI46JrRZN7KV5Ac5bQWzF9ZMPeHqmq5FBdY
               ooIF8W7lVtYx23OQX5vjFRN0LRY8hyOKL07Us+aUeMwDXX7M6o58XO4bqOh8pGOq
               FLscCAkdAP9lDgeDGwIDAQAB
               -----END PUBLIC KEY-----
               KEY
  wrong_key = OpenSSL::PKey::RSA.new(1024).to_pem

  describe "#decode_jwt" do
    it "with public_key" do
      provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
        client_id: "test-client", client_secret: "test-secret",
        public_key: public_key

      jwt = JWT.encode({"foo" => "bar"}, private_key, JWT::Algorithm::RS256)

      payload, header = provider.decode_jwt(jwt)
      payload.should eq({"foo" => "bar"})

      jwt = JWT.encode({"foo" => "bar"}, wrong_key, JWT::Algorithm::RS256)

      expect_raises(JWT::VerificationError, "Signature verification failed") do
        provider.decode_jwt(jwt)
      end
    end

    it "without public_key" do
      provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
        client_id: "test-client", client_secret: "test-secret"

      jwt = JWT.encode({"foo" => "bar"}, private_key, JWT::Algorithm::RS256)

      payload, header = provider.decode_jwt(jwt)
      payload.should eq({"foo" => "bar"})
    end
  end

  describe "#get_id_token" do
    it "makes request" do
      orig_id_token = OpenIDConnect::IDToken.new "https://login.example.com", "foobar", ["test-client"]
      encoded_id_token = JWT.encode(JSON.parse(orig_id_token.to_json), private_key, JWT::Algorithm::RS256)

      handler = HTTP::Handler::HandlerProc.new do |context|
        context.request.method.should eq "POST"
        context.request.path.should eq "/oauth2/token"
        context.request.body.try(&.gets_to_end).should eq "redirect_uri=https%3A%2F%2Fexample.com%2Fredirect&grant_type=authorization_code&code=enemenemu"
        context.request.headers["Accept"].should eq "application/json"
        context.request.headers["Content-Type"].should eq "application/x-www-form-urlencoded"
        context.request.headers["Authorization"].should eq "Basic dGVzdC1jbGllbnQ6dGVzdC1zZWNyZXQ="

        {
          access_token:  "token123",
          id_token:      encoded_id_token,
          refresh_token: "token345",
        }.to_json(context.response)
      end

      run_handler(handler) do |http_client|
        provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
          client_id: "test-client", client_secret: "test-secret",
          redirect_uri: "https://example.com/redirect"

        provider.client.http_client = http_client

        id_token, access_token = provider.get_id_token?("enemenemu")
        id_token.should eq orig_id_token

        access_token.access_token.should eq "token123"
        access_token.refresh_token.should eq "token345"
      end
    end

    it "error response" do
      handler = HTTP::Handler::HandlerProc.new do |context|
        context.response.respond_with_status :unauthorized
      end

      run_handler(handler) do |http_client|
        provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
          client_id: "test-client", client_secret: "test-secret",
          redirect_uri: "https://example.com/redirect"

        provider.client.http_client = http_client

        expect_raises OAuth2::Error, "401 Unauthorized" do
          provider.get_id_token("enemenemu")
        end
      end
    end

    it "missing id_token" do
      handler = HTTP::Handler::HandlerProc.new do |context|
        {
          access_token:  "token123",
          refresh_token: "token345",
        }.to_json(context.response)
      end

      run_handler(handler) do |http_client|
        provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
          client_id: "test-client", client_secret: "test-secret",
          redirect_uri: "https://example.com/redirect"

        provider.client.http_client = http_client

        expect_raises OAuth2::Error, "Invalid response: Missing id_token" do
          provider.get_id_token("enemenemu")
        end
      end
    end

    it "access_token with token_type mac" do
      handler = HTTP::Handler::HandlerProc.new do |context|
        OAuth2::AccessToken::Mac.new("token1234", 7200, "hmac-sha-256", "secret key").to_json(context.response)
      end

      run_handler(handler) do |http_client|
        provider = OpenIDConnect::Provider.new URI.parse("https://login.example.com"),
          client_id: "test-client", client_secret: "test-secret",
          redirect_uri: "https://example.com/redirect"

        provider.client.http_client = http_client

        expect_raises OAuth2::Error, "Invalid response: Missing id_token" do
          provider.get_id_token("enemenemu")
        end
      end
    end
  end
end
