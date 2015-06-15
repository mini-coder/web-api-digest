using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Remoting.Messaging;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

using System.IdentityModel.Tokens;

using System.Configuration;
using DigestDemo.Secutiry;
namespace DigestDemo.Digest
{
    public class AuthenticationHandler : DelegatingHandler
    {
        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            try
            {
                HttpRequestHeaders headers = request.Headers;
                if (headers.Authorization != null)
                {
                    Header header = new Header(request.Headers.Authorization.Parameter, request.Method.Method);

                    if (Nonce.IsValid(header.Nonce, header.NounceCounter))
                    {
                        string uzkey = ConfigurationManager.AppSettings["UZKey"];
                        string uzsecret = ConfigurationManager.AppSettings["UZSecret"];

                        string ha1 = HashHelper.GetMD5(String.Format("{0}:{1}:{2}", uzkey, header.Realm, uzsecret));

                        string ha2 = HashHelper.GetMD5(String.Format("{0}:{1}", header.Method, header.Uri));

                        string computedResponse = HashHelper.GetMD5(String.Format("{0}:{1}:{2}:{3}:{4}:{5}",
                                            ha1, header.Nonce, header.NounceCounter, header.Cnonce, "auth", ha2));

                        if (String.CompareOrdinal(header.Response, computedResponse) == 0)
                        {
                            // digest computed matches the value sent by client in the response field.
                            // Looks like an authentic client! Create a principal.
                            var claims = new List<Claim>
                        {
                                        new Claim(ClaimTypes.Name, header.UserName),
                                        new Claim(ClaimTypes.AuthenticationMethod,AuthenticationMethods.Password)
                        };

                            ClaimsPrincipal principal = new ClaimsPrincipal(new[] { new ClaimsIdentity(claims, "Digest") });

                            Thread.CurrentPrincipal = principal;

                            if (HttpContext.Current != null)
                                HttpContext.Current.User = principal;
                        }
                    }
                }

                HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Digest", Header.UnauthorizedResponseHeader.ToString()));
                }

                return response;
            }
            catch (Exception)
            {
                var response = request.CreateResponse(HttpStatusCode.Unauthorized);
                response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Digest", Header.UnauthorizedResponseHeader.ToString()));

                return response;
            }
        }
    }
}