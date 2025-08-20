using DH.Permissions.Identity.JwtBearer;
using DH.Permissions.Identity.JwtBearer.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Pek.Security;

namespace DH.Permissions.Examples;

/// <summary>
/// Token验证优化示例
/// 展示如何使用新的缓存机制来避免重复解析Token
/// </summary>
public class TokenValidationOptimizationExample
{
    private readonly IJsonWebTokenValidator _validator;
    private readonly JwtOptions _options;
    
    public TokenValidationOptimizationExample(IJsonWebTokenValidator validator, IOptions<JwtOptions> options)
    {
        _validator = validator;
        _options = options.Value;
    }
    
    /// <summary>
    /// 传统方式：每次都重新解析Token（性能较差）
    /// </summary>
    public void TraditionalApproach(String token)
    {
        Console.WriteLine("=== 传统方式（重复解析）===");
        
        // 第一次验证 - 解析Token
        var isValid1 = _validator.IsValidToken(token, _options);
        Console.WriteLine($"第一次验证: {isValid1}");
        
        // 第二次验证 - 再次解析Token
        var isValid2 = _validator.Validate(token, _options, (payload, options) => 
        {
            // 自定义验证逻辑
            return payload.ContainsKey("sub");
        });
        Console.WriteLine($"第二次验证: {isValid2}");
        
        // 第三次验证 - 又一次解析Token
        var isValid3 = _validator.IsValidToken(token, _options);
        Console.WriteLine($"第三次验证: {isValid3}");
        
        Console.WriteLine("问题：Token被解析了3次，造成性能浪费\n");
    }
    
    /// <summary>
    /// 优化方式：使用缓存避免重复解析（性能更好）
    /// </summary>
    public void OptimizedApproach(String token, HttpContext httpContext)
    {
        Console.WriteLine("=== 优化方式（使用缓存）===");
        
        // 第一次验证 - 解析Token并缓存结果
        var result1 = GetValidationResultWithCache(token, httpContext);
        Console.WriteLine($"第一次验证: {result1.IsValid} (解析并缓存)");
        
        // 第二次验证 - 从缓存获取结果
        var result2 = GetValidationResultWithCache(token, httpContext);
        Console.WriteLine($"第二次验证: {result2.IsValid} (从缓存获取)");
        
        // 第三次验证 - 从缓存获取结果
        var result3 = GetValidationResultWithCache(token, httpContext);
        Console.WriteLine($"第三次验证: {result3.IsValid} (从缓存获取)");
        
        // 可以直接使用缓存的payload数据
        if (result3.IsValid && result3.Payload != null)
        {
            Console.WriteLine("可以直接使用缓存的Payload数据:");
            foreach (var kvp in result3.Payload)
            {
                Console.WriteLine($"  {kvp.Key}: {kvp.Value}");
            }
        }
        
        Console.WriteLine("优势：Token只解析了1次，后续使用缓存结果\n");
    }
    
    /// <summary>
    /// 获取验证结果（带缓存）
    /// </summary>
    private TokenValidationResult GetValidationResultWithCache(String token, HttpContext httpContext)
    {
        // 尝试从缓存获取
        var cachedResult = TokenValidationCache.GetCachedResult(httpContext, token);
        if (cachedResult != null)
        {
            return cachedResult;
        }
        
        // 缓存中没有，进行验证并缓存结果
        var result = _validator.ValidateWithResult(token, _options, (payload, options) => 
        {
            // 自定义验证逻辑
            return payload.ContainsKey("sub");
        });
        
        TokenValidationCache.SetCachedResult(httpContext, token, result);
        return result;
    }
    
    /// <summary>
    /// 演示在实际应用中的使用场景
    /// </summary>
    public void RealWorldScenarioExample(String token, HttpContext httpContext)
    {
        Console.WriteLine("=== 实际应用场景示例 ===");
        
        try
        {
            // 1. 中间件中的验证
            var middlewareResult = ValidateInMiddleware(token, httpContext);
            Console.WriteLine($"中间件验证: {middlewareResult.IsValid}");
            
            // 2. 授权处理器中的验证（使用缓存）
            var authHandlerResult = ValidateInAuthorizationHandler(token, httpContext);
            Console.WriteLine($"授权处理器验证: {authHandlerResult.IsValid}");
            
            // 3. 业务逻辑中需要用户信息（使用缓存）
            var userInfo = GetUserInfoFromToken(token, httpContext);
            Console.WriteLine($"获取用户信息: UserId={userInfo?.UserId}, ClientId={userInfo?.ClientId}");
            
            Console.WriteLine("整个请求过程中Token只被解析了1次！");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"验证失败: {ex.Message}");
        }
        
        Console.WriteLine();
    }
    
    /// <summary>
    /// 模拟中间件中的验证
    /// </summary>
    private TokenValidationResult ValidateInMiddleware(String token, HttpContext httpContext)
    {
        var result = _validator.ValidateWithResult(token, _options, (payload, options) => true);
        TokenValidationCache.SetCachedResult(httpContext, token, result);
        
        if (!result.IsValid)
            throw new UnauthorizedAccessException("Token验证失败");
            
        return result;
    }
    
    /// <summary>
    /// 模拟授权处理器中的验证
    /// </summary>
    private TokenValidationResult ValidateInAuthorizationHandler(String token, HttpContext httpContext)
    {
        // 从缓存获取结果，避免重复解析
        var cachedResult = TokenValidationCache.GetCachedResult(httpContext, token);
        if (cachedResult != null)
            return cachedResult;
            
        // 理论上不应该到这里，因为中间件已经验证过了
        throw new InvalidOperationException("缓存中应该已经有验证结果");
    }
    
    /// <summary>
    /// 从Token中获取用户信息
    /// </summary>
    private UserInfo GetUserInfoFromToken(String token, HttpContext httpContext)
    {
        var cachedResult = TokenValidationCache.GetCachedResult(httpContext, token);
        if (cachedResult?.IsValid != true || cachedResult.Payload == null)
            return null;
            
        return new UserInfo
        {
            UserId = cachedResult.Payload.GetValueOrDefault("sub"),
            ClientId = cachedResult.Payload.GetValueOrDefault("clientId"),
            UserName = cachedResult.Payload.GetValueOrDefault("name"),
            Email = cachedResult.Payload.GetValueOrDefault("email")
        };
    }
    
    /// <summary>
    /// 用户信息类
    /// </summary>
    public class UserInfo
    {
        public String UserId { get; set; }
        public String ClientId { get; set; }
        public String UserName { get; set; }
        public String Email { get; set; }
    }
}

/// <summary>
/// 示例运行器
/// </summary>
public static class OptimizationExampleRunner
{
    public static void RunExample()
    {
        // 模拟配置
        var options = Options.Create(new JwtOptions
        {
            Secret = "your-secret-key-here-must-be-at-least-32-characters-long",
            Issuer = "test-issuer",
            Audience = "test-audience"
        });
        
        var validator = new JsonWebTokenValidator(options);
        var example = new TokenValidationOptimizationExample(validator, options);
        
        // 生成测试Token（这里应该使用实际的Token生成逻辑）
        var testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJjbGllbnRJZCI6InRlc3QtY2xpZW50IiwibmFtZSI6IlRlc3QgVXNlciIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImV4cCI6OTk5OTk5OTk5OX0.test-signature";
        
        var httpContext = new DefaultHttpContext();
        
        Console.WriteLine("JWT Token验证优化示例\n");
        
        // 演示传统方式
        example.TraditionalApproach(testToken);
        
        // 演示优化方式
        example.OptimizedApproach(testToken, httpContext);
        
        // 清理缓存
        TokenValidationCache.ClearAllCachedResults(httpContext);
        
        // 演示实际应用场景
        example.RealWorldScenarioExample(testToken, httpContext);
    }
}
