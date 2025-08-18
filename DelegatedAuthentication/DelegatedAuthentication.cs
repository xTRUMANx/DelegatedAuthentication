using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication;

namespace DelegatedAuthentication
{
    public class DelegatedAuthentication
    {
        private readonly RequestDelegate next;
        private DelegatedAuthenticationOptions options;

        public DelegatedAuthentication(RequestDelegate next, DelegatedAuthenticationOptions options)
        {
            this.next = next;

            this.options = options;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (options.IgnoredPaths.Any(context.Request.Path.Value.StartsWith) || options.IgnoredPathExtensions.Any(context.Request.Path.Value.EndsWith))
            {
                await next(context);

                return;
            }

            var loginPage = options.LoginPage;

            if (loginPage.StartsWith("/"))
            {
                loginPage = BuildAbsoluteUrlBasedOnRequest(context, loginPage);
            }

            var cookie = GetCookie(context);

            if (string.IsNullOrWhiteSpace(cookie))
            {
                if (options.CallSignInAndSignOut && IsAuthenticated(context))
                {
                    await context.SignOutAsync();
                }

                if(options.RedirectToLoginPage) context.Response.Redirect(loginPage);
                else await next(context);

                return;
            }

            DelegatedAuthenticationResponse? res = await GetDelegatedAuthenticationResponseAsync(context);

            if (!IsAuthenticated(context) || (res?.IsAuthenticated == true && res?.Id!.Equals(context.User.Identity!.Name) == false))
            {
                await DoDelegatedAuth(context, res);
            }

            if (context.User.Identity?.IsAuthenticated == false && options.RedirectToLoginPage)
            {
                context.Response.Redirect(loginPage);
            }
            else
            {
                await next(context);
            }
        }

        bool IsAuthenticated(HttpContext context) => context.User.Identity?.IsAuthenticated == true;

        private async Task<DelegatedAuthenticationResponse?> GetDelegatedAuthenticationResponseAsync(HttpContext context)
        {
            return string.IsNullOrWhiteSpace(options.ForceLoginAs)
                        ? await CallAuthEndpoint(context)
                        : new() { Id = options.ForceLoginAs, IsAuthenticated = true };
        }

        private async Task DoDelegatedAuth(HttpContext context, DelegatedAuthenticationResponse? res)
        {
            if (res == null || !res.IsAuthenticated || string.IsNullOrWhiteSpace(res.Id))
            {
                return;
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, res.Id),
            };

            var claimsIdentity = new ClaimsIdentity(claims, options.AuthenticationScheme);

            var principal = new ClaimsPrincipal(claimsIdentity);

            if(options.CallSignInAndSignOut) await context.SignInAsync(options.AuthenticationScheme, principal);

            context.User = principal;
        }

        private async Task<DelegatedAuthenticationResponse?> CallAuthEndpoint(HttpContext context)
        {
            if (!context.Request.Cookies.Any(c => c.Key == options.CookieName)) return null;

            var httpClient = options.HttpMessageHandler == null
                            ? new HttpClient()
                            : new HttpClient(options.HttpMessageHandler);

            var cookie = GetCookie(context);
            httpClient.DefaultRequestHeaders.Add("Cookie", $"{options.CookieName}={cookie}");

            var authEndpoint = options.AuthEndpoint;

            if (authEndpoint.StartsWith("/"))
            {
                authEndpoint = BuildAbsoluteUrlBasedOnRequest(context, authEndpoint);
            }

            var res = await httpClient.GetFromJsonAsync<DelegatedAuthenticationResponse>(authEndpoint);

            return res;
        }

        string? GetCookie(HttpContext context) => context.Request.Cookies[options.CookieName];

        string BuildAbsoluteUrlBasedOnRequest(HttpContext context, string relativeUrl) => $"{context.Request.Scheme}://{context.Request.Host}{relativeUrl}";
    }

    class DelegatedAuthenticationResponse
    {
        public bool IsAuthenticated { get; set; }

        public string? Id { get; set; }
    }

    public class DelegatedAuthenticationOptions
    {
        /// <summary>
        /// If set to a non-empty value, delegated authentication process is skipped and user is logged in as the value.
        /// </summary>
        public string? ForceLoginAs { get; set; }

        /// <summary>
        /// If set to true, the middleware will call SignInAsync and SignOutAsync on the context. Defaults to true.
        /// </summary>
        public bool CallSignInAndSignOut { get; set; } = true;

        /// <summary>
        /// If set to true, the middleware will redirect the user to the login page if they are not authenticated. Defaults to true.
        /// </summary>
        public bool RedirectToLoginPage { get; set; } = true;

        /// <summary>
        /// Endpoint to fetch authentication information from. Required if ForceLoginAs is not set.
        /// </summary>
        public string AuthEndpoint { get; set; } = null!;

        /// <summary>
        /// Authentication scheme to use on sign in. Required.
        /// </summary>
        public string AuthenticationScheme { get; set; } = null!;

        /// <summary>
        /// Cookie name used on sign in. Defaults to ".ASPXAUTH".
        /// </summary>
        public string CookieName { get; set; } = ".ASPXAUTH";

        /// <summary>
        /// Login page URL to redirect user to if they are not logged in. Required if RedirectToLoginPage is true.
        /// </summary>
        public string LoginPage { get; set; } = null!;

        public string[] IgnoredPaths { get; set; } = [];

        public string[] IgnoredPathExtensions { get; set; } = [];

        /// <summary>
        /// Passed to the HttpClient used to call the AuthEndpoint.
        /// </summary>
        /// 
        public HttpMessageHandler? HttpMessageHandler { get; set; }

        public void Validate()
        {
            if (CallSignInAndSignOut && string.IsNullOrWhiteSpace(AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(AuthenticationScheme), $"{nameof(AuthenticationScheme)} must be specifed.");
            }

            if (string.IsNullOrWhiteSpace(ForceLoginAs))
            {
                if (string.IsNullOrWhiteSpace(AuthEndpoint))
                {
                    throw new ArgumentNullException(nameof(AuthEndpoint), $"{nameof(AuthEndpoint)} must be specifed.");
                }
            }

            if (RedirectToLoginPage && string.IsNullOrWhiteSpace(LoginPage))
            {
                throw new ArgumentNullException(nameof(LoginPage), $"{nameof(LoginPage)} must be specifed.");
            }
        }
    }

    public static class DelegatedAuthenticationExtensions
    {
        public static IServiceCollection AddDelegatedAuthentication(this IServiceCollection services, Action<DelegatedAuthenticationOptions> setupAction)
        {
            var options = new DelegatedAuthenticationOptions();

            setupAction.Invoke(options);

            options.Validate();

            services.AddSingleton(options);

            return services;
        }

        public static IApplicationBuilder UseDelegatedAuth(this IApplicationBuilder app, Action<DelegatedAuthenticationOptions>? setupAction = null)
        {
            DelegatedAuthenticationOptions options = (app.ApplicationServices.GetService(typeof(DelegatedAuthenticationOptions)) as DelegatedAuthenticationOptions) ?? new();

            setupAction?.Invoke(options);

            options.Validate();

            return app.UseMiddleware<DelegatedAuthentication>(options);
        }
    }
}
