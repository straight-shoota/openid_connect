# require "./spec_helper"

# describe OpenIDConnect do
#   it "flow" do
#     provider = OpenIDConnect::Provider.new(
#       "https://keycloak.rabanus.kath.de/auth/realms/kath.de",
#       authorize_endpoint: "protocol/openid-connect/auth",
#       token_endpoint: "protocol/openid-connect/token",
#       #userinfo_endpoint: "protocol/openid-connect/userinfo",
#       client_id: "client_id",
#       client_secret: "client_secret",
#       redirect_uri: "/redirect_uri"
#     )

#     on_login = -> do
#       http_redirect provider.get_authorize_uri, :found
#     end

#     on_redirect = -> do
#       authorization_code = request.params["code"]

#       access_token = provider.get_access_token(authorization_code)
#     end

#   end
# end
