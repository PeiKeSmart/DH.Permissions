using System.Diagnostics;
using DH.Permissions.Identity.JwtBearer;
using DH.Permissions.Identity.JwtBearer.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Pek.Security;

namespace DH.Permissions.Examples;

/// <summary>
/// Token验证性能测试
/// 用于验证Token解析缓存优化的效果
/// </summary>
public class TokenValidationPerformanceTest
{
    private readonly IJsonWebTokenValidator _validator;
    private readonly JwtOptions _options;
    
    public TokenValidationPerformanceTest()
    {
        _options = new JwtOptions
        {
            Secret = "your-secret-key-here-must-be-at-least-32-characters-long",
            Issuer = "test-issuer",
            Audience = "test-audience"
        };
        
        _validator = new JsonWebTokenValidator(Options.Create(_options));
    }
    
    /// <summary>
    /// 测试传统方式的重复解析性能
    /// </summary>
    public void TestTraditionalRepeatedParsing()
    {
        var token = GenerateTestToken();
        var iterations = 1000;
        
        var stopwatch = Stopwatch.StartNew();
        
        for (int i = 0; i < iterations; i++)
        {
            // 模拟传统方式：每次都重新解析
            var isValid1 = _validator.IsValidToken(token, _options);
            var payload1 = GetPayloadTraditional(token);
            
            var isValid2 = _validator.Validate(token, _options, (payload, options) => true);
            var payload2 = GetPayloadTraditional(token);
            
            var isValid3 = _validator.IsValidToken(token, _options);
            var payload3 = GetPayloadTraditional(token);
        }
        
        stopwatch.Stop();
        Console.WriteLine($"传统方式 - {iterations} 次迭代，每次3次重复解析");
        Console.WriteLine($"总耗时: {stopwatch.ElapsedMilliseconds} ms");
        Console.WriteLine($"平均每次迭代: {stopwatch.ElapsedMilliseconds / (double)iterations:F2} ms");
        Console.WriteLine($"平均每次解析: {stopwatch.ElapsedMilliseconds / (double)(iterations * 3):F2} ms");
    }
    
    /// <summary>
    /// 测试优化后的缓存方式性能
    /// </summary>
    public void TestOptimizedCachedParsing()
    {
        var token = GenerateTestToken();
        var iterations = 1000;
        
        var stopwatch = Stopwatch.StartNew();
        
        for (int i = 0; i < iterations; i++)
        {
            // 模拟优化后的方式：使用缓存
            var httpContext = new DefaultHttpContext();
            
            // 第一次解析并缓存
            var result1 = _validator.IsValidTokenWithResult(token, _options);
            TokenValidationCache.SetCachedResult(httpContext, token, result1);
            
            // 后续使用缓存
            var cachedResult2 = TokenValidationCache.GetCachedResult(httpContext, token);
            var cachedResult3 = TokenValidationCache.GetCachedResult(httpContext, token);
            
            // 清理缓存为下次迭代准备
            TokenValidationCache.ClearAllCachedResults(httpContext);
        }
        
        stopwatch.Stop();
        Console.WriteLine($"\n优化方式 - {iterations} 次迭代，每次1次解析+2次缓存读取");
        Console.WriteLine($"总耗时: {stopwatch.ElapsedMilliseconds} ms");
        Console.WriteLine($"平均每次迭代: {stopwatch.ElapsedMilliseconds / (double)iterations:F2} ms");
        Console.WriteLine($"平均每次操作: {stopwatch.ElapsedMilliseconds / (double)(iterations * 3):F2} ms");
    }
    
    /// <summary>
    /// 运行完整的性能对比测试
    /// </summary>
    public void RunPerformanceComparison()
    {
        Console.WriteLine("=== JWT Token解析性能对比测试 ===\n");
        
        // 预热
        Console.WriteLine("预热中...");
        var warmupToken = GenerateTestToken();
        for (int i = 0; i < 100; i++)
        {
            _validator.IsValidToken(warmupToken, _options);
        }
        
        Console.WriteLine("开始性能测试...\n");
        
        // 测试传统方式
        TestTraditionalRepeatedParsing();
        
        // 测试优化方式
        TestOptimizedCachedParsing();
        
        Console.WriteLine("\n=== 测试完成 ===");
    }
    
    /// <summary>
    /// 测试缓存功能的正确性
    /// </summary>
    public void TestCacheFunctionality()
    {
        Console.WriteLine("\n=== 缓存功能正确性测试 ===");
        
        var token = GenerateTestToken();
        var httpContext = new DefaultHttpContext();
        
        // 测试缓存不存在时返回null
        var cachedResult = TokenValidationCache.GetCachedResult(httpContext, token);
        Console.WriteLine($"缓存不存在时: {(cachedResult == null ? "✓ 正确返回null" : "✗ 错误")}");
        
        // 测试设置和获取缓存
        var originalResult = _validator.IsValidTokenWithResult(token, _options);
        TokenValidationCache.SetCachedResult(httpContext, token, originalResult);
        
        var retrievedResult = TokenValidationCache.GetCachedResult(httpContext, token);
        Console.WriteLine($"缓存设置和获取: {(retrievedResult != null && retrievedResult.IsValid == originalResult.IsValid ? "✓ 正确" : "✗ 错误")}");
        
        // 测试清除缓存
        TokenValidationCache.ClearAllCachedResults(httpContext);
        var clearedResult = TokenValidationCache.GetCachedResult(httpContext, token);
        Console.WriteLine($"缓存清除: {(clearedResult == null ? "✓ 正确" : "✗ 错误")}");
        
        Console.WriteLine("=== 缓存功能测试完成 ===\n");
    }
    
    /// <summary>
    /// 生成测试用的Token
    /// </summary>
    private String GenerateTestToken()
    {
        // 这里应该使用实际的JWT生成逻辑
        // 为了测试，我们创建一个简单的有效Token结构
        var header = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        
        var payload = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{{\"sub\":\"test-user\",\"exp\":{DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}}}"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        
        var signature = Convert.ToBase64String(System.Security.Cryptography.HMACSHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(_options.Secret),
            System.Text.Encoding.UTF8.GetBytes($"{header}.{payload}")))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        
        return $"{header}.{payload}.{signature}";
    }
    
    /// <summary>
    /// 传统的Payload解析方式（用于性能对比）
    /// </summary>
    private Dictionary<String, String> GetPayloadTraditional(String token)
    {
        var jwtArray = token.Split('.');
        if (jwtArray.Length < 3)
            throw new ArgumentException("无效的JWT Token");
        
        var payloadJson = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(jwtArray[1].PadRight(jwtArray[1].Length + (4 - jwtArray[1].Length % 4) % 4, '=')));
        
        // 简单的JSON解析（实际应该使用JsonHelper）
        return new Dictionary<String, String>();
    }
}

/// <summary>
/// 测试运行器
/// </summary>
public static class PerformanceTestRunner
{
    public static void RunTests()
    {
        var test = new TokenValidationPerformanceTest();
        
        // 运行缓存功能测试
        test.TestCacheFunctionality();
        
        // 运行性能对比测试
        test.RunPerformanceComparison();
    }
}
