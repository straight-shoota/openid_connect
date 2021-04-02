require "spec"
require "../src/id_token"

describe OpenIDConnect::IDToken do
  describe ".from_json" do
    it "parses" do
      token = OpenIDConnect::IDToken.from_json(<<-JSON)
        {
          "exp": 1613479117,
          "iat": 1613478817,
          "auth_time": 1613478816,
          "nonce": "123456",
          "iss": "https://login.example.com",
          "aud": ["oidc-crystal"],
          "sub": "foobar",
          "azp": "oidc-crystal",
          "at_hash": "JnRWI-vTCk4wwHijyBG2UA",
          "acr": "1",
          "email": "openid-connect@crystal-lang.org"
        }
        JSON
      token.expires.should eq Time.utc(2021, 2, 16, 12, 38, 37)
      token.auth_time.should eq Time.utc(2021, 2, 16, 12, 33, 36)
      token.issued_at.should eq Time.utc(2021, 2, 16, 12, 33, 37)
      token.issuer.should eq "https://login.example.com"
      token.subject.should eq "foobar"
      token.audience.should eq ["oidc-crystal"]
      token.nonce.should eq "123456"
      token.authentication_context_class_reference.should eq "1"
      token.authentication_methods_references.should be_nil
      token.authorized_party.should eq "oidc-crystal"
      token.access_token_hash.should eq "JnRWI-vTCk4wwHijyBG2UA"
      token.json_unmapped["email"].should eq "openid-connect@crystal-lang.org"
    end

    it "parses string audience" do
      token = OpenIDConnect::IDToken.from_json(<<-JSON)
        {
          "exp": 1613479117,
          "iat": 1613478817,
          "auth_time": 1613478816,
          "iss": "https://login.example.com",
          "aud": ["oidc-crystal"],
          "sub": "foobar"
        }
        JSON
      token.expires.should eq Time.utc(2021, 2, 16, 12, 38, 37)
      token.auth_time.should eq Time.utc(2021, 2, 16, 12, 33, 36)
      token.issued_at.should eq Time.utc(2021, 2, 16, 12, 33, 37)
      token.issuer.should eq "https://login.example.com"
      token.subject.should eq "foobar"
      token.audience.should eq ["oidc-crystal"]
    end

    it "fails" do
      expect_raises(JSON::SerializableError, "Missing JSON attribute: iss") do
        OpenIDConnect::IDToken.from_json("{}")
      end
      expect_raises(JSON::SerializableError, "Missing JSON attribute: sub") do
        OpenIDConnect::IDToken.from_json(<<-JSON)
          {
            "iss": "https://login.example.com"
          }
          JSON
      end
      expect_raises(JSON::SerializableError, "Missing JSON attribute: aud") do
        OpenIDConnect::IDToken.from_json(<<-JSON)
          {
            "iss": "https://login.example.com",
            "sub": "foobar"
          }
          JSON
      end
    end
  end

  it "#expired?" do
    clock = Time.utc
    token = OpenIDConnect::IDToken.new("https://login.example.com", "foobar", ["oidc-crystal"], expires: clock)
    token.expired?(clock - 1.second).should be_false
    token.expired?(clock + 1.second).should be_true
  end

  it "#valid?" do
    token = OpenIDConnect::IDToken.new("https://login.example.com", "foobar", ["oidc-crystal"])
    token.valid?.should be_true
    token.copy_with(expires: Time.utc - 1.minute).valid?.should be_false
  end

  it "#validate!" do
    token = OpenIDConnect::IDToken.new("https://login.example.com", "foobar", ["oidc-crystal"])
    token.validate!

    token.validate!(issuer: "https://login.example.com")
    expect_raises OpenIDConnect::IDToken::InvalidTokenError, "Issuer does not match" do
      token.validate!(issuer: "https://other.example.com")
    end

    token.validate!(client_id: "oidc-crystal", authorized_party: nil)
    expect_raises OpenIDConnect::IDToken::InvalidTokenError, "Audience does not match" do
      token.validate!(client_id: "oidc-other")
    end

    token2 = token.copy_with(nonce: "12345")
    token2.validate!(nonce: "12345")
    expect_raises OpenIDConnect::IDToken::InvalidTokenError, "Nonce does not match" do
      token2.validate!(nonce: "invalid")
    end

    token3 = token.copy_with(expires: Time.utc - 1.minute)
    expect_raises OpenIDConnect::IDToken::InvalidTokenError, "Expired token" do
      token3.validate!
    end
  end

  it "#==" do
    token = OpenIDConnect::IDToken.new("https://login.example.com", "foobar", ["oidc-crystal"])
    token.should eq token
    OpenIDConnect::IDToken.from_json(token.to_json).should eq token
  end
end
