using Pek.Exceptions;

namespace DH.Permissions.Identity.JwtBearer;

/// <summary>
/// JWT刷新令牌异常
/// </summary>
public class JwtRefreshException : Warning
{
    /// <summary>
    /// 错误码
    /// </summary>
    public Int32 ErrCode { get; set; }

    /// <summary>
    /// 初始化一个<see cref="JwtRefreshException"/>类型的实例
    /// </summary>
    /// <param name="message">异常消息</param>
    /// <param name="errCode">错误码,默认9994表示刷新令牌不存在或已过期</param>
    public JwtRefreshException(String message, Int32 errCode = 9994) : base(message)
    {
        ErrCode = errCode;
    }

    /// <summary>
    /// 初始化一个<see cref="JwtRefreshException"/>类型的实例
    /// </summary>
    /// <param name="message">异常消息</param>
    /// <param name="errCode">错误码</param>
    /// <param name="innerException">内部异常</param>
    public JwtRefreshException(String message, Int32 errCode, Exception innerException) : base(message)
    {
        ErrCode = errCode;
    }
}
