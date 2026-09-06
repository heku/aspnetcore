// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Authorization.Policy;

// IEffectiveAuthenticationSchemeSelector  Task<IEnumerable<string>?> SelectEffectiveSchemeAsync(HttpContext context);
// IEffectiveAuthorizationPolicySelector   Task<AuthorizationPolicy?> SelectEffectivePolicyAsync(HttpContext context);

internal sealed class EffectiveAuthorizationPolicySelector : IEffectiveAuthorizationPolicySelector, IEffectiveAuthenticationSchemeSelector
{
    private readonly IAuthorizationPolicyProvider _policyProvider;
    private readonly bool _canCache;
    private readonly AuthorizationPolicyCache? _policyCache;

    internal EffectiveAuthorizationPolicySelector(IAuthorizationPolicyProvider policyProvider)
    {
        _policyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
        _canCache = false;
    }

    public EffectiveAuthorizationPolicySelector(IAuthorizationPolicyProvider policyProvider, IServiceProvider services)
    {
        _policyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
        if (_policyProvider.AllowsCachingPolicies)
        {
            ArgumentNullException.ThrowIfNull(services);
            _policyCache = services.GetService<AuthorizationPolicyCache>();
            _canCache = _policyCache != null;
        }
    }

    public async Task<AuthorizationPolicy?> SelectEffectivePolicyAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();

        // Use the computed policy for this endpoint if we can
        AuthorizationPolicy? policy = null;
        var canCachePolicy = _canCache && endpoint != null;
        if (canCachePolicy)
        {
            policy = _policyCache!.Lookup(endpoint!);
        }

        if (policy == null)
        {
            // The middleware evaluates all the authorization metadata associated with the endpoint at once.
            // IMPORTANT: Changes to authorization logic should be mirrored in MVC's AuthorizeFilter
            var metadata = (IEnumerable<object>?)endpoint?.Metadata ?? Array.Empty<object>();

            policy = await AuthorizationPolicy.CombineAsync(_policyProvider, metadata);

            // Cache the computed policy
            if (policy != null && canCachePolicy)
            {
                _policyCache!.Store(endpoint!, policy);
            }
        }

        return policy;
    }

    public async Task<IEnumerable<string>?> SelectEffectiveSchemeAsync(HttpContext context)
    {
        var policy = await SelectEffectivePolicyAsync(context);
        return policy?.AuthenticationSchemes;
    }
}
