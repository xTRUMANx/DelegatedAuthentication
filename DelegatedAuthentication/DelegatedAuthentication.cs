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
            if ((context.User.Identity?.IsAuthenticated) != true && context.Request.Cookies.Any(c => c.Key == options.CookieName))
            {
                await DoDelegatedAuth(context);
            }

            await next(context);
        }

        private async Task DoDelegatedAuth(HttpContext context)
        {
            var httpClient = new HttpClient();

            var cookie = context.Request.Cookies[options.CookieName];
            httpClient.DefaultRequestHeaders.Add("Cookie", $"{options.CookieName}={cookie}");

            var res = await httpClient.GetFromJsonAsync<DelegatedAuthenticationResponse>(options.AuthEndpoint);

            if (res == null || !res.IsAuthenticated || string.IsNullOrWhiteSpace(res.Id))
            {
                context.Response.Redirect(options.LoginPage);

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
    }

    class DelegatedAuthenticationResponse
    {
        public bool IsAuthenticated { get; set; }

        public string? Id { get; set; }
    }

    public class DelegatedAuthenticationOptions
    {
        /// <summary>
        /// Endpoint to fetch authentication information from. Required.
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
        /// Login page URL to redirect user to if they are not logged in. Required.
        /// </summary>
        public string LoginPage { get; set; } = null!;

        public void Validate()
        {
            if (string.IsNullOrWhiteSpace(AuthEndpoint))
            {
                throw new ArgumentNullException(nameof(AuthEndpoint), $"{nameof(AuthEndpoint)} must be specifed.");
            }

            if (string.IsNullOrWhiteSpace(AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(AuthenticationScheme), $"{nameof(AuthenticationScheme)} must be specifed.");
            }

            if (string.IsNullOrWhiteSpace(LoginPage))
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
