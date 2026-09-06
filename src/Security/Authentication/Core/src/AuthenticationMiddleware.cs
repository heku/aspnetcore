// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;

namespace Microsoft.AspNetCore.Authentication;

/// <summary>
/// Middleware that performs authentication.
/// </summary>
public class AuthenticationMiddleware
{
    private static readonly bool UseEndpointSpecificAuthenticationScheme = AppContext.TryGetSwitch("Microsoft.AspNetCore.Authentication.UseEndpointSpecificAuthenticationScheme", out var isEnabled) && isEnabled;

    private readonly RequestDelegate _next;

    /// <summary>
    /// Initializes a new instance of <see cref="AuthenticationMiddleware"/>.
    /// </summary>
    /// <param name="next">The next item in the middleware pipeline.</param>
    /// <param name="schemes">The <see cref="IAuthenticationSchemeProvider"/>.</param>
    public AuthenticationMiddleware(RequestDelegate next, IAuthenticationSchemeProvider schemes, IEffectiveAuthenticationSchemeSelector schemesSelector)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(schemes);

        _next = next;
        Schemes = schemes;
        SchemesSelector = schemesSelector;
    }

    /// <summary>
    /// Gets or sets the <see cref="IAuthenticationSchemeProvider"/>.
    /// </summary>
    public IAuthenticationSchemeProvider Schemes { get; set; }

    public IEffectiveAuthenticationSchemeSelector SchemesSelector { get; }

    /// <summary>
    /// Invokes the middleware performing authentication.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/>.</param>
    public async Task Invoke(HttpContext context)
    {
        context.Features.Set<IAuthenticationFeature>(new AuthenticationFeature
        {
            OriginalPath = context.Request.Path,
            OriginalPathBase = context.Request.PathBase
        });

        IEnumerable<string>? activeSchemes = null;
        IEnumerable<AuthenticationScheme>? requestHandlerSchemes = await Schemes.GetRequestHandlerSchemesAsync();

        if (UseEndpointSpecificAuthenticationScheme)
        {
            activeSchemes = await SchemesSelector.SelectEffectiveSchemeAsync(context);
            if (activeSchemes == null || !activeSchemes.Any())
            {
                var defaultAuthenticate = await Schemes.GetDefaultAuthenticateSchemeAsync();
                activeSchemes = defaultAuthenticate == null ? null : [defaultAuthenticate.Name];
            }
            if (activeSchemes != null)
            {
                requestHandlerSchemes = requestHandlerSchemes.Where(scheme => activeSchemes.Contains(scheme.Name, StringComparer.Ordinal));
            }
        }
        else
        {
            var defaultAuthenticate = await Schemes.GetDefaultAuthenticateSchemeAsync();
            activeSchemes = defaultAuthenticate == null ? null : [defaultAuthenticate.Name];
        }

        // Give any IAuthenticationRequestHandler schemes a chance to handle the request
        var handlers = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
        foreach (var scheme in requestHandlerSchemes)
        {
            var handler = await handlers.GetHandlerAsync(context, scheme.Name) as IAuthenticationRequestHandler;
            if (handler != null && await handler.HandleRequestAsync())
            {
                return;
            }
        }

        if (activeSchemes != null)
        {
            await AuthenticateAsync(activeSchemes, context);
        }

        await _next(context);
    }

    internal static async Task AuthenticateAsync(IEnumerable<string> schemes, HttpContext context)
    {
        if (schemes?.Any() is true)
        {
            ClaimsPrincipal? newPrincipal = null;
            DateTimeOffset? minExpiresUtc = null;
            foreach (var scheme in schemes)
            {
                var result = await context.AuthenticateAsync(scheme);
                if (result != null && result.Succeeded)
                {
                    newPrincipal = SecurityHelper.MergeUserPrincipal(newPrincipal, result.Principal);

                    if (minExpiresUtc is null || result.Properties?.ExpiresUtc < minExpiresUtc)
                    {
                        minExpiresUtc = result.Properties?.ExpiresUtc;
                    }
                }
            }

            if (newPrincipal != null)
            {
                context.User = newPrincipal;

                var ticket = new AuthenticationTicket(newPrincipal, string.Join(';', schemes));
                // ExpiresUtc is the easiest property to reason about when dealing with multiple schemes
                // SignalR will use this property to evaluate auth expiration for long running connections
                ticket.Properties.ExpiresUtc = minExpiresUtc;

                var result = AuthenticateResult.Success(ticket);
                var authFeatures = new AuthenticationFeatures(result);
                context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
                context.Features.Set<IAuthenticateResultFeature>(authFeatures);
            }
            else
            {
                context.User = new ClaimsPrincipal(new ClaimsIdentity());

                // TODO: set or not?
                // context.Features.Set<IHttpAuthenticationFeature>(User);
                // context.Features.Set<IAuthenticateResultFeature>(null);
            }
        }
    }
}
