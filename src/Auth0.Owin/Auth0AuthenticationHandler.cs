using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Auth0.Owin
{
    internal class Auth0AuthenticationHandler : AuthenticationHandler<Auth0AuthenticationOptions>
    {

        #region Constants

        private const string DefaultIssuer = "LOCAL AUTHORITY";
        private const string AuthorizeEndpoint = "https://{0}/authorize";
        private const string TokenEndpoint = "https://{0}/oauth/token";
        private const string UserInfoEndpoint = "https://{0}/userinfo";

        #endregion

        private static readonly string[] ClaimTypesForUserId = { "userid" };
        private static readonly string[] ClaimTypesForRoles = { "roles", "role" };
        private static readonly string[] ClaimTypesForEmail = { "emails", "email" };
        private static readonly string[] ClaimTypesForGivenName = { "givenname", "firstname" };
        private static readonly string[] ClaimTypesForFamilyName = { "familyname", "lastname", "surname" };
        private static readonly string[] ClaimTypesForPostalCode = { "postalcode" };
        private static readonly string[] ClaimsToExclude = { "iss", "sub", "aud", "exp", "iat", "identities" };

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public Auth0AuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            string code = null;
            string state = null;

            try
            {
                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);

                if (code == null)
                {
                    // Null if the remote server returns an error.
                    return new AuthenticationTicket(null, properties);
                }

                var tokenRequestParameters = string.Format(
                    CultureInfo.InvariantCulture,
                    "client_id={0}&redirect_uri={1}&client_secret={2}&code={3}&grant_type=authorization_code",
                    Uri.EscapeDataString(Options.ClientId),
                    Uri.EscapeDataString(GenerateRedirectUri(properties)),
                    Uri.EscapeDataString(Options.ClientSecret),
                    code);

                var body = new Dictionary<string, string> {
                    { "client_id", Options.ClientId },
                    { "redirect_uri", GenerateRedirectUri(properties) },
                    { "client_secret", Options.ClientSecret },
                    { "code", Uri.EscapeDataString(code) },
                    { "grant_type", "authorization_code" }
                };

                //RWM: Use Auth0.Portable instead and replace these calls with API calls.
                HttpResponseMessage tokenResponse = await _httpClient.PostAsync(string.Format(TokenEndpoint, Options.Domain), new FormUrlEncodedContent(body), Request.CallCancelled);
                await EnsureTokenExchangeSuccessful(tokenResponse);
                string text = await tokenResponse.Content.ReadAsStringAsync();
                JObject tokens = JObject.Parse(text);

                string accessToken = tokens["access_token"].Value<string>();
                string idToken = tokens["id_token"] != null ? tokens["id_token"].Value<string>() : null;
                string refreshToken = tokens["refresh_token"] != null ? tokens["refresh_token"].Value<string>() : null;
				
                //RWM: Use Auth0.Portable instead and replace these calls with API calls.
                HttpResponseMessage graphResponse = await _httpClient.GetAsync(
                   string.Format(UserInfoEndpoint, Options.Domain) + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();
                text = await graphResponse.Content.ReadAsStringAsync();
                JObject user = JObject.Parse(text);

                //RWM: We're still using this for now because it is tied to other parts of the code. However it is likely unnecessary.
                var context = new Auth0AuthenticatedContext(Context, user, accessToken, idToken, refreshToken);
                
                //RWM: Create claims for every item in the payload, using standard claims wherever possible.
                var payloadData = JsonConvert.DeserializeObject<Dictionary<string, object>>(text);
                var claims = GetClaimsFromJwt(payloadData, Constants.Auth0Issuer);
                var identity = GetClaimsIdentity(claims, Options.AuthenticationType, Constants.Auth0Issuer);

                //RWM: Provided for backwards-compatibility.
                if (!string.IsNullOrWhiteSpace(context.Email))
                {
                    identity.AddClaim(new Claim("email", context.Email, ClaimValueTypes.String, context.Connection, Constants.Auth0Issuer));
                }

                //RWM: Add in the claims that are not part of the User object.
                if (!string.IsNullOrWhiteSpace(context.Provider)) identity.AddClaim(new Claim("provider", context.Provider, ClaimValueTypes.String, context.Connection, Constants.Auth0Issuer));
                if (!string.IsNullOrWhiteSpace(context.ProviderAccessToken)) identity.AddClaim(new Claim("provider_access_token", context.ProviderAccessToken, ClaimValueTypes.String, context.Connection, Constants.Auth0Issuer));
                if (Options.SaveIdToken && !string.IsNullOrWhiteSpace(context.IdToken)) identity.AddClaim(new Claim("id_token", context.IdToken, ClaimValueTypes.String, Constants.Auth0Issuer));
                identity.AddClaim(new Claim("access_token", context.AccessToken, ClaimValueTypes.String, Constants.Auth0Issuer));

                context.Identity = new ClaimsIdentity(identity);
                context.Properties = properties ?? new AuthenticationProperties();

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                var tokenExchangeFailedContext = new Auth0TokenExchangeFailedContext(
                    Context, Options,
                    ex, code, state);
                Options.Provider.TokenExchangeFailed(tokenExchangeFailedContext);

                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        /// <summary>
        /// Gets a List of Claims from a given deserialized JSON token.
        /// </summary>
        /// <param name="jwtData">The deserialized JSON payload to process.</param>
        /// <param name="issuer">The principal that issued the JWT.</param>
        /// <returns>A List of Claims derived from the JWT.</returns>
        private static IEnumerable<Claim> GetClaimsFromJwt(Dictionary<string, object> jwtData, string issuer)
        {
            var list = new List<Claim>();
            issuer = issuer ?? DefaultIssuer;

            foreach (var pair in jwtData)
            {
                var claimType = GetClaimType(pair.Key);
                var type = pair.Value.GetType();
                var source = pair.Value as JArray;

                if (source != null)
                {
                    // Get the claim, check to make sure it hasn't already been added. This is a workaround
                    // for an issue where MicrosoftAccounts return the same e-mail address twice.
                    foreach (var innerClaim in source.Cast<object>().Select(item => new Claim(claimType, item.ToString(), ClaimValueTypes.String, issuer, issuer))
                        .Where(innerClaim => !list.Any(c => c.Type == innerClaim.Type && c.Value == innerClaim.Value)))
                    {
                        list.Add(innerClaim);
                    }

                    continue;
                }

                var claim = new Claim(claimType, pair.Value.ToString(), ClaimValueTypes.String, issuer, issuer);
                if (!list.Contains(claim))
                {
                    list.Add(claim);
                }
            }

            // dont include specific jwt claims
            return list.Where(c => ClaimsToExclude.All(t => t != c.Type)).ToList();
        }

        /// <summary>
        /// Gets a <see cref="ClaimsIdentity"/> properly populated with the claims from the JWT.
        /// </summary>
        /// <param name="claims">The list of claims that we've already processed.</param>
        /// <param name="authenticationType">The AuthenticationType to use for the ClaimsIdentity.</param>
        /// <param name="issuer">The principal that issued the JWT.</param>
        /// <returns></returns>
        private static ClaimsIdentity GetClaimsIdentity(IEnumerable<Claim> claims, string authenticationType, string issuer)
        {
            var subject = new ClaimsIdentity(authenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

            foreach (var claim in claims)
            {
                var type = claim.Type;
                if (type == ClaimTypes.Actor)
                {
                    if (subject.Actor != null)
                    {
                        throw new InvalidOperationException(string.Format(
                            "Jwt10401: Only a single 'Actor' is supported. Found second claim of type: '{0}', value: '{1}'", new object[] { "actor", claim.Value }));
                    }
                }

                var claim3 = new Claim(type, claim.Value, claim.ValueType, issuer, issuer, subject);
                subject.AddClaim(claim3);
            }

            return subject;
        }

        /// <summary>
        /// Gets the Standard Claim name for the property, if available.
        /// </summary>
        /// <param name="name">The property name as sent by Auth0.</param>
        /// <returns></returns>
        private static string GetClaimType(string name)
        {
            var newName = name.Replace("_", "").ToLower();
            if (newName == "name")
            {
                return ClaimTypes.Name;
            }
            if (ClaimTypesForUserId.Contains(newName))
            {
                return ClaimTypes.NameIdentifier;
            }
            if (ClaimTypesForRoles.Contains(newName))
            {
                return ClaimTypes.Role;
            }
            if (ClaimTypesForEmail.Contains(newName))
            {
                return ClaimTypes.Email;
            }
            if (ClaimTypesForGivenName.Contains(newName))
            {
                return ClaimTypes.GivenName;
            }
            if (ClaimTypesForFamilyName.Contains(newName))
            {
                return ClaimTypes.Surname;
            }
            if (ClaimTypesForPostalCode.Contains(newName))
            {
                return ClaimTypes.PostalCode;
            }
            if (name == "gender")
            {
                return ClaimTypes.Gender;
            }

            return name;
        }

        private async Task EnsureTokenExchangeSuccessful(HttpResponseMessage tokenResponse)
        {
            if (!tokenResponse.IsSuccessStatusCode)
            {
                string errorResponse = null;

                try
                {
                    errorResponse = await tokenResponse.Content.ReadAsStringAsync();
                    tokenResponse.EnsureSuccessStatusCode();
                }
                catch (Exception ex)
                {
                    throw new TokenExchangeFailedException(errorResponse, ex);
                }
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // comma separated
                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint =
                    string.Format(AuthorizeEndpoint, Options.Domain) +
                        "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                        "&connection=" + Uri.EscapeDataString(Options.Connection ?? string.Empty) +
                        "&response_type=code" +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&state=" + Uri.EscapeDataString(state) +
                        (Options.Scope.Count > 0 ? "&scope=" + Uri.EscapeDataString(string.Join(" ", Options.Scope)) : string.Empty);

                var redirectContext = new Auth0ApplyRedirectContext(
                    Context, Options,
                    properties, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                if (Request.Query["error"] != null)
                {
                    _logger.WriteVerbose("Remote server returned an error: " + Request.QueryString);

                    var redirectUrl = Options.RedirectPath + Request.QueryString;
                    Response.Redirect(redirectUrl);
                    return true;
                }

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new Auth0ReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties != null ? ticket.Properties.RedirectUri : null;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted)
                {
                    string redirectUri = context.RedirectUri ?? Options.RedirectPath.ToString();
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }

                    if (context.Request.Query["state"] != null && context.Request.Query["state"].Contains("ru="))
                    {
                        // set returnUrl with state -> ru
                        var state = HttpUtilities.ParseQueryString(context.Request.Query["state"]);
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "returnUrl", state["ru"]);
                    }

                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }

        private string GenerateRedirectUri(AuthenticationProperties properties)
        {
            string requestPrefix = Request.Scheme + "://" + Request.Host;

            string redirectUri = requestPrefix + RequestPathBase + Options.CallbackPath; // + "?state=" + Uri.EscapeDataString(Options.StateDataHandler.Protect(state));          

            var context = new Auth0CustomizeTokenExchangeRedirectUriContext(Request.Context, Options, properties, redirectUri);
            Options.Provider.CustomizeTokenExchangeRedirectUri(context);

            return context.RedirectUri;
        }
    }
}
