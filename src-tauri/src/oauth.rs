use std::io::{BufReader, BufRead};
use std::net::TcpListener;
use oauth2::{ClientId, ClientSecret, AuthUrl, TokenUrl, RedirectUrl, RevocationUrl, Scope, CsrfToken, PkceCodeChallenge, AuthorizationCode, StandardRevocableToken};
use oauth2::basic::BasicClient;
use oauth2::url::Url;
use oauth2::reqwest::http_client;

#[tauri::command]
async fn handle_google_oauth(app: tauri::AppHandle, window: tauri::Window) -> Result<(), String> {
  if window.label() != "main" {
    println!("OAuth flow being initiated by non-main window");
    return Err("OAuth flow being initiated by non-main window".to_owned());
  }

  // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
  // token URL.
  let client = create_google_oauth_client()?;
    
  // Generate the authorization URL to which we'll redirect the user.
  let (authorize_url, csrf_state) = generate_auth_url_with_google_mail_scopes(&client);

  // TODO: open oauth window and set url to authorize_url
   

  Ok(())
}

fn create_google_oauth_client() -> Result<BasicClient, String> {
  let google_client_id = ClientId::new("clientId".to_string());
  let google_client_secret = ClientSecret::new("clientSecret".to_string());
  let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
    .map_err(|err| format!("{}: {}", "Invalid authorization endpoint URL", err.to_string()))?;
  let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
    .map_err(|err| format!("{}: {}", "Invalid token endpoint URL", err.to_string()))?;

  let client = BasicClient::new(
    google_client_id,
    Some(google_client_secret),
    auth_url,
    Some(token_url)
  )
  // Set the URL the user will be redirected to after the authorization process.
  .set_redirect_uri(
    RedirectUrl::new("http://localhost:62884".to_string())
      .map_err(|err| format!("Bad Redirect URL: {}", err.to_string()))?
  )
  .set_revocation_uri(
    RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())
      .map_err(|err| format!("Invalid revocation endpoint URL: {}", err.to_string()))?
  );
  Ok(client)
}

fn generate_auth_url_with_google_mail_scopes(client: &BasicClient) -> (Url, CsrfToken) {
  // Google supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
  // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
  let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();
  client
    .authorize_url(CsrfToken::new_random)
    // This example is requesting access to the "calendar" features and the user's profile.
    .add_scope(Scope::new(
        "https://www.googleapis.com/auth/calendar".to_string(),
    ))
    .add_scope(Scope::new(
        "https://www.googleapis.com/auth/plus.me".to_string(),
    ))
    .set_pkce_challenge(pkce_code_challenge)
    .url()
}

fn listen_for_oauth_response(client: &BasicClient) -> Result<(), String> {
  // A very naive implementation of the redirect server.
  let listener = TcpListener::bind("127.0.0.1:62884").unwrap();
  for stream in listener.incoming() {
    if let Ok(mut stream) = stream {
      let code;
      let state;
      {
        let mut reader = BufReader::new(&stream);

        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();

        let redirect_url = request_line.split_whitespace().nth(1).unwrap();
        let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

        let code_pair = url
            .query_pairs()
            .find(|pair| {
                let &(ref key, _) = pair;
                key == "code"
            })
            .unwrap();

        let (_, value) = code_pair;
        code = AuthorizationCode::new(value.into_owned());

        let state_pair = url
            .query_pairs()
            .find(|pair| {
                let &(ref key, _) = pair;
                key == "state"
            })
            .unwrap();

        let (_, value) = state_pair;
        state = CsrfToken::new(value.into_owned());
      }

      let message = "Go back to your terminal :)";
      let response = format!(
          "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
          message.len(),
          message
      );
      stream.write_all(response.as_bytes()).unwrap();

      println!("Google returned the following code:\n{}\n", code.secret());
      println!(
          "Google returned the following state:\n{} (expected `{}`)\n",
          state.secret(),
          csrf_state.secret()
      );

      // Exchange the code with a token.
      let token_response = client
          .exchange_code(code)
          .set_pkce_verifier(pkce_code_verifier)
          .request(http_client);

      println!(
          "Google returned the following token:\n{:?}\n",
          token_response
      );

      // Revoke the obtained token
      let token_response = token_response.unwrap();
      let token_to_revoke: StandardRevocableToken = match token_response.refresh_token() {
          Some(token) => token.into(),
          None => token_response.access_token().into(),
      };

      client
          .revoke_token(token_to_revoke)
          .unwrap()
          .request(http_client)
          .expect("Failed to revoke token");

      // The server will terminate itself after revoking the token.
      break;
    }
  }
  Ok(())
}
