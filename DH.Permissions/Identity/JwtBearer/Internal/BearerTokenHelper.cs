namespace DH.Permissions.Identity.JwtBearer.Internal;

/// <summary>Bearer令牌解析辅助类</summary>
internal static class BearerTokenHelper
{
    private const String BearerPrefix = "Bearer ";

    /// <summary>尝试从授权头中提取Token</summary>
    /// <param name="authorizationHeader">授权头内容</param>
    /// <param name="token">提取出的Token</param>
    /// <param name="requireBearerPrefix">是否要求Bearer前缀</param>
    /// <returns>是否提取成功</returns>
    public static Boolean TryGetToken(String authorizationHeader, out String token, Boolean requireBearerPrefix = false)
    {
        token = null;
        if (String.IsNullOrWhiteSpace(authorizationHeader))
            return false;

        var tokenSpan = authorizationHeader.AsSpan().Trim();
        if (tokenSpan.IsEmpty)
            return false;

        if (tokenSpan.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            tokenSpan = tokenSpan[BearerPrefix.Length..].Trim();
        }
        else
        {
            if (requireBearerPrefix)
                return false;

            var separatorIndex = tokenSpan.LastIndexOf(' ');
            if (separatorIndex >= 0)
                tokenSpan = tokenSpan[(separatorIndex + 1)..].Trim();
        }

        if (tokenSpan.IsEmpty)
            return false;

        token = tokenSpan.ToString();
        return true;
    }
}