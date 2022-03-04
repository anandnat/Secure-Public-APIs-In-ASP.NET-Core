

namespace SPADNC.Api.Filters
{
    using System;
    using System.Net;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Filters;
    using Microsoft.Extensions.Caching.Memory;
    [AttributeUsage(AttributeTargets.Method)]
    public class RequestLimit : ActionFilterAttribute
    {
        public RequestLimit(string name)
        {
            Name = name;
        }
        public string Name
        {
            get;
        }
        public int NoOfRequest
        {
            get;
            set;
        } = 1;
        public int Seconds
    {
        get;
        set;
    } = 1;
    private static MemoryCache memoryCache
        {
            get;
        } = new MemoryCache(new MemoryCacheOptions());

public override void OnActionExecuting(ActionExecutingContext context)
{
    var ipAddress = context.HttpContext.Request.HttpContext.Connection.RemoteIpAddress;
    var memoryCacheKey = $"{Name}-{ipAddress}";
    memoryCache.TryGetValue(memoryCacheKey, out int prevReqCount);
    if (prevReqCount >= NoOfRequest)
    {
        context.Result = new ContentResult
        {
            Content = $"Request is exceeded. Try again in seconds.",
        };
        context.HttpContext.Response.StatusCode = (int)HttpStatusCode.TooManyRequests;
    }
    else
    {
        var cacheEntryOptions = new MemoryCacheEntryOptions().SetAbsoluteExpiration(TimeSpan.FromSeconds(Seconds));
        memoryCache.Set(memoryCacheKey, (prevReqCount + 1), cacheEntryOptions);
    }
}
    }
}
