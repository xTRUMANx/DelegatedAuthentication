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
            if ((context.User.Identity?.IsAuthenticated) == false)
            {
                await DoDelegatedAuth(context);
            }

            if (context.User.Identity?.IsAuthenticated == false && !string.IsNullOrWhiteSpace(options.LoginPage))
            {
                context.Response.Redirect(options.LoginPage);
            }
            else
            {
                await next(context);
            }
        }

        private async Task DoDelegatedAuth(HttpContext context)
        {
            DelegatedAuthenticationResponse? res = string.IsNullOrWhiteSpace(options.ForceLoginAs)
                ? await CallAuthEndpoint(context)
                : new() { Id = options.ForceLoginAs, IsAuthenticated = true };

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

            await context.SignInAsync(options.AuthenticationScheme, principal);

            context.User = principal;
        }

        private async Task<DelegatedAuthenticationResponse?> CallAuthEndpoint(HttpContext context)
        {
            if (!context.Request.Cookies.Any(c => c.Key == options.CookieName)) return null;

            var httpClient = options.HttpMessageHandler == null
                            ? new HttpClient()
                            : new HttpClient(options.HttpMessageHandler);

            var cookie = context.Request.Cookies[options.CookieName];
            httpClient.DefaultRequestHeaders.Add("Cookie", $"{options.CookieName}={cookie}");

            var res = await httpClient.GetFromJsonAsync<DelegatedAuthenticationResponse>(options.AuthEndpoint);

            return res;
        }
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
        /// Login page URL to redirect user to if they are not logged in. Required if ForceLoginAs is not set.
        /// </summary>
        public string LoginPage { get; set; } = null!;

        /// <summary>
        /// Passed to the HttpClient used to call the AuthEndpoint.
        /// </summary>
        public HttpMessageHandler? HttpMessageHandler { get; set; }

        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(AuthenticationScheme), $"{nameof(AuthenticationScheme)} must be specifed.");
            }

            if (string.IsNullOrWhiteSpace(ForceLoginAs))
            {
                if (string.IsNullOrWhiteSpace(AuthEndpoint))
                {
                    throw new ArgumentNullException(nameof(AuthEndpoint), $"{nameof(AuthEndpoint)} must be specifed.");
                }

                if (string.IsNullOrWhiteSpace(LoginPage))
                {
                    throw new ArgumentNullException(nameof(LoginPage), $"{nameof(LoginPage)} must be specifed.");
                }
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
