// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Authorization;

// This middleware exists to force the correct constructor overload to be called when the user calls UseAuthorization().
// Since we already expose the AuthorizationMiddleware type, we can't change the constructor signature without breaking it.
internal sealed class AuthorizationMiddlewareInternal(
    RequestDelegate next,
    IEffectiveAuthorizationPolicySelector policyProvider,
    ILogger<AuthorizationMiddleware> logger) : AuthorizationMiddleware(next, policyProvider, logger)
{
}

/// <summary>
/// A middleware that enables authorization capabilities.
/// </summary>
public class AuthorizationMiddleware
{
    // AppContext switch used to control whether HttpContext or endpoint is passed as a resource to AuthZ
    private const string SuppressUseHttpContextAsAuthorizationResource = "Microsoft.AspNetCore.Authorization.SuppressUseHttpContextAsAuthorizationResource";

    private static readonly bool _suppressUseHttpContextAsAuthorizationResource = AppContext.TryGetSwitch(SuppressUseHttpContextAsAuthorizationResource, out var enabled) && enabled;

    // Property key is used by Endpoint routing to determine if Authorization has run
    private const string AuthorizationMiddlewareInvokedWithEndpointKey = "__AuthorizationMiddlewareWithEndpointInvoked";

    private static readonly object AuthorizationMiddlewareWithEndpointInvokedValue = new object();

    private static readonly bool UseEndpointSpecificAuthenticationScheme = AppContext.TryGetSwitch("Microsoft.AspNetCore.Authentication.UseEndpointSpecificAuthenticationScheme", out var isEnabled) && isEnabled;

    private readonly RequestDelegate _next;
    private readonly IEffectiveAuthorizationPolicySelector _policySelector;
    private readonly ILogger<AuthorizationMiddleware>? _logger;

    /// <summary>
    /// Initializes a new instance of <see cref="AuthorizationMiddleware"/>.
    /// </summary>
    /// <param name="next">The next middleware in the application middleware pipeline.</param>
    /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/>.</param>
    [Obsolete]
    public AuthorizationMiddleware(RequestDelegate next,
          IAuthorizationPolicyProvider policyProvider)
    {
        ArgumentNullException.ThrowIfNull(policyProvider);
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _policySelector = new EffectiveAuthorizationPolicySelector(policyProvider);
    }

    /// <summary>
    /// Initializes a new instance of <see cref="AuthorizationMiddleware"/>.
    /// </summary>
    /// <param name="next">The next middleware in the application middleware pipeline.</param>
    /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/>.</param>
    /// <param name="services">The <see cref="IServiceProvider"/>.</param>
    /// <param name="logger">The <see cref="ILogger"/>.</param>
    [Obsolete]
    public AuthorizationMiddleware(RequestDelegate next,
        IAuthorizationPolicyProvider policyProvider,
        IServiceProvider services,
        ILogger<AuthorizationMiddleware> logger) : this(next, policyProvider, services)
    {
        _logger = logger;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="AuthorizationMiddleware"/>.
    /// </summary>
    /// <param name="next">The next middleware in the application middleware pipeline.</param>
    /// <param name="policyProvider">The <see cref="IAuthorizationPolicyProvider"/>.</param>
    /// <param name="services">The <see cref="IServiceProvider"/>.</param>
    [Obsolete]
    public AuthorizationMiddleware(RequestDelegate next,
        IAuthorizationPolicyProvider policyProvider,
        IServiceProvider services) : this(next, policyProvider)
    {
        ArgumentNullException.ThrowIfNull(services);
        _policySelector = new EffectiveAuthorizationPolicySelector(policyProvider, services);
    }

    public AuthorizationMiddleware(RequestDelegate next,
        IEffectiveAuthorizationPolicySelector policyProvider,
        ILogger<AuthorizationMiddleware> logger)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _policySelector = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
        _logger = logger;
    }

    /// <summary>
    /// Invokes the middleware performing authorization.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/>.</param>
    public async Task Invoke(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var endpoint = context.GetEndpoint();
        if (endpoint != null)
        {
            // EndpointRoutingMiddleware uses this flag to check if the Authorization middleware processed auth metadata on the endpoint.
            // The Authorization middleware can only make this claim if it observes an actual endpoint.
            context.Items[AuthorizationMiddlewareInvokedWithEndpointKey] = AuthorizationMiddlewareWithEndpointInvokedValue;
        }

        var policy = await _policySelector.SelectEffectivePolicyAsync(context);
        if (policy == null)
        {
            await _next(context);
            return;
        }

        IPolicyEvaluator policyEvaluator = null;
        AuthenticateResult authenticateResult = null;

        if (UseEndpointSpecificAuthenticationScheme)
        {
            // Allow Anonymous still wants to run authorization to populate the User but skips any failure/challenge handling
            if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null)
            {
                await _next(context);
                return;
            }

            authenticateResult = context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult;
            if (authenticateResult is null)
            {
                // TODO: UseAuthentication() must be add ...
                throw null;
            }
        }
        else
        {
            // Policy evaluator has transient lifetime so it's fetched from request services instead of injecting in constructor
            policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();
            authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);
            if (authenticateResult?.Succeeded ?? false)
            {
                if (context.Features.Get<IAuthenticateResultFeature>() is IAuthenticateResultFeature authenticateResultFeature)
                {
                    authenticateResultFeature.AuthenticateResult = authenticateResult;
                }
                else
                {
                    var authFeatures = new AuthenticationFeatures(authenticateResult);
                    context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
                    context.Features.Set<IAuthenticateResultFeature>(authFeatures);
                }
            }

            // Allow Anonymous still wants to run authorization to populate the User but skips any failure/challenge handling
            if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null)
            {
                await _next(context);
                return;
            }

            if (authenticateResult != null && !authenticateResult.Succeeded && _logger is ILogger log && log.IsEnabled(LogLevel.Debug))
            {
                log.LogDebug("Policy authentication schemes {policyName} did not succeed", String.Join(", ", policy.AuthenticationSchemes));
            }
        }

        object? resource;
        if (_suppressUseHttpContextAsAuthorizationResource)
        {
            resource = endpoint;
        }
        else
        {
            resource = context;
        }

        var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult!, context, resource);
        var authorizationMiddlewareResultHandler = context.RequestServices.GetRequiredService<IAuthorizationMiddlewareResultHandler>();
        await authorizationMiddlewareResultHandler.HandleAsync(_next, context, policy, authorizeResult);
    }
}
