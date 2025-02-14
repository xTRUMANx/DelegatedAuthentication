using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication;

namespace DelegatedAuthentication
{
    public class DelegatedAuthenticationMiddleware
    {
        private readonly RequestDelegate next;
        private DelegatedAuthenticationMiddlewareOptions options;

        public DelegatedAuthenticationMiddleware(RequestDelegate next, DelegatedAuthenticationMiddlewareOptions options)
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

            if (res == null || !res.IsAuthenticated || string.IsNullOrWhiteSpace(res.Id)) return;

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

    public class DelegatedAuthenticationMiddlewareOptions
    {
        public string AuthEndpoint { get; set; } = null!;

        public string AuthenticationScheme { get; set; } = null!;

        public string CookieName { get; set; } = ".ASPXAUTH";
    }

    public static class DelegatedAuthenticationMiddlewareExtensions
    {
        public static IServiceCollection AddDelegatedAuthenticationMiddleware(this IServiceCollection services, Action<DelegatedAuthenticationMiddlewareOptions> setupAction)
        {
            var options = new DelegatedAuthenticationMiddlewareOptions();

            setupAction.Invoke(options);

            if (string.IsNullOrWhiteSpace(options.AuthEndpoint))
            {
                throw new ArgumentNullException(nameof(options.AuthEndpoint), $"{nameof(options.AuthEndpoint)} must be specifed.");
            }

            if (string.IsNullOrWhiteSpace(options.AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(options.AuthenticationScheme), $"{nameof(options.AuthenticationScheme)} must be specifed.");
            }

            services.AddSingleton(options);

            return services;
        }

        public static IApplicationBuilder UseDelegatedAuthMiddleware(
            this IApplicationBuilder app, Action<DelegatedAuthenticationMiddlewareOptions>? setupAction = null)
        {
            DelegatedAuthenticationMiddlewareOptions options = (app.ApplicationServices.GetService(typeof(DelegatedAuthenticationMiddlewareOptions)) as DelegatedAuthenticationMiddlewareOptions) ?? new();

            setupAction?.Invoke(options);

            if (string.IsNullOrWhiteSpace(options.AuthEndpoint))
            {
                throw new ArgumentNullException(nameof(options.AuthEndpoint), $"{nameof(options.AuthEndpoint)} must be specifed.");
            }

            if (string.IsNullOrWhiteSpace(options.AuthenticationScheme))
            {
                throw new ArgumentNullException(nameof(options.AuthenticationScheme), $"{nameof(options.AuthenticationScheme)} must be specifed.");
            }

            return app.UseMiddleware<DelegatedAuthenticationMiddleware>(options);
        }
    }
}
