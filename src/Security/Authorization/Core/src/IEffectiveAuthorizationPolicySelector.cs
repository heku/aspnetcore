// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authorization;

public interface IEffectiveAuthorizationPolicySelector
{
    Task<AuthorizationPolicy?> SelectEffectivePolicyAsync(HttpContext context);
}
