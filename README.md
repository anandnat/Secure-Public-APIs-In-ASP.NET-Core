# Secure Public APIs In ASP.NET Core
ASP.NET Core is a popular structure. Its key advantages include features such as cross-platform execution, high performance, built-in dependency injection and modular HTTP request pipeline.

## The challenge
The ASP.NET Core provides support for many authentication providers to secure applications through numerous authentication workflows. However, in many scenarios, we have to provide a web application/site that is based on an unauthenticated API with anonymous access.

For example, we have a list of products in the database and we want to display these products on a web page. We can write an API to provide a list of products and the front end (web site) can receive this list through the API and display it on our public products web page.

Without applying a level of security, such architectures can be an open security vulnerability to exploitation.

## Available Security Controls in ASP.NET

ASP.NET Provides solutions for common vulnerabilities including core 

- Cross-site scripting
- SQL injection,
- Cross-Site Request Forgery (CSRF)
- Open redirects

## Going a step further
As developers, we should also protect our applications from other common attack vectors including

- Distributed denial-of-service (DDOS)
- Denial-of-service (DOS)
- Bulk data egress
- Probe response
- Scraping
The two steps we can take careof to verify the referrer header and rate-limiting, discussed below in detail.

## Use IP based request limit action filter
We can limit customers to a certain number of requests over a specified period of time to prevent malicious bot attacks.We havecreated IP based requestlimitactionfilter in the ASP.NET Core. Keep in mind that multiple clients can sit behind a single IP address so you can meet this within your limits, or combine the IP address with other request data to make requests more unique.

To try the filter, you just need to add an ActionAttribute at the top of the controller action.

```sh
using SPADNC.Api.Filters;


        [HttpGet]
        [ValidateReferrer]
        [RequestLimit("Get-WeatherForecast", NoOfRequest = 3, Seconds = 10)]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }
```

Here is the implementation of the filter: 
[RequestAttribute.cs](/RequestAttribute.cs)

```sh
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

```
