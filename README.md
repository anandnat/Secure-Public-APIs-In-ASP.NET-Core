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
[RequestAttribute.cs](Secure-Public-APIs-Dot-Net-Core/Filters/RequestAttribute.cs)

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
## Add referrercheck action filter
To protect the API from abuse and to provide additional protection against Cross-Site Request Forgery (CSRF) attacks, security checks are performed on the request referrer header for each REST API request sent to the server.

This API validates where the request comes from. We have created a Referrer Check Action Filter in ASP.NET Core. It prevents access to tools like POSTMEN, REST client, etc.

You just need to do is add an ActionAttribute to the top of the controller Action.

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

Here is the implementation of the filter [ValidateReferrer.cs](Secure-Public-APIs-Dot-Net-Core/Filters/ValidateReferrer.cs)


```sh

namespace SPADNC.Api.Filters
{
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Filters;
    using Microsoft.Extensions.Configuration;
    using System;
    using System.Linq;
    using System.Net;
    /// <summary>    
    /// ActionFilterAttribute to validate referrer url    
    /// </summary>    
    /// <seealso cref="Microsoft.AspNetCore.Mvc.Filters.ActionFilterAttribute" />    
    [AttributeUsage(AttributeTargets.Method)]
    public sealed class ValidateReferrerAttribute : ActionFilterAttribute
    {
        private IConfiguration _configuration;
        /// <summary>    
        /// Initializes a new instance of the <see cref="ValidateReferrerAttribute"/> class.    
        /// </summary>    
        public ValidateReferrerAttribute() { }
        /// <summary>    
        /// Called when /[action executing].    
        /// </summary>    
        /// <param name="context">The action context.</param>    
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            _configuration = (IConfiguration)context.HttpContext.RequestServices.GetService(typeof(IConfiguration));
            base.OnActionExecuting(context);
            if (!IsValidRequest(context.HttpContext.Request))
            {
                context.Result = new ContentResult
                {
                    Content = $"Invalid referer header"
                };
                context.HttpContext.Response.StatusCode = (int)HttpStatusCode.ExpectationFailed;
            }
        }
        /// <summary>    
        /// Determines whether /[is valid request] [the specified request].    
        /// </summary>    
        /// <param name="request">The request.</param>    
        /// <returns>    
        /// <c>true</c> if [is valid request] [the specified request]; otherwise, <c>false</c>.    
        /// </returns>    
        private bool IsValidRequest(HttpRequest request)
        {
            string referrerURL = "";
            if (request.Headers.ContainsKey("Referer"))
            {
                referrerURL = request.Headers["Referer"];
            }
            if (string.IsNullOrWhiteSpace(referrerURL)) return false;
            // get allowed client list to check    
            var allowedUrls = _configuration.GetSection("CorsOrigin").Get<string[]>()?.Select(url => new Uri(url).Authority).ToList();
            //add current host for swagger calls    
            var host = request.Host.Value;
            allowedUrls.Add(host);
            bool isValidClient = allowedUrls.Contains(new Uri(referrerURL).Authority); // comapre with base uri    
            return isValidClient;
        }
    }
}

```


## Add DoSattack middleware
If you have the auto scale configured, DOS attacks overwhelm your APIs, making them unauthorized and/or expensive. There are various ways to avoid this problem by request throttling. There is an option here to use intermediaries to restrict the number of requests from particulate client IP addresses.

Below is the code for [DosAttackMiddleware.cs](Secure-Public-APIs-Dot-Net-Core/Filters/DosAttackMiddleware.cs)

```sh


namespace SPADNC.Api.Middlewares
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Http;
    using System.Timers;
    public class DosAttackMiddleware
    {
        public class IpadressModel
        {
            public string IpAddress { get; set; }
            public short Counter { get; set; }
        }
        #region Private fields
        private static readonly List<IpadressModel> IpAdresses = new List<IpadressModel>();
        private static readonly Stack<string> Banned = new Stack<string>();
        private static Timer _timer = CreateTimer();
        private static Timer _bannedTimer = CreateBanningTimer();

        private const int BannedRequests = 10;
        private const int ReductionInterval = 1000; // 1 second
        private const int ReleaseInterval = 1 * 60 * 1000; // 1 minutes
        #endregion

        #region Middleware Members
        private RequestDelegate _next;
        public DosAttackMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        public async Task Invoke(HttpContext context)
        {
            // Do something with context near the beginning of request processing.
            string ip = context.Request.HttpContext.Connection.RemoteIpAddress.ToString();

            CheckIpAddress(ip);

            if (Banned.Contains(ip))
            {
                context.Response.StatusCode = 403;

            }
            else
            {
                await _next.Invoke(context);
            }
        }
        #endregion

        private static void CheckIpAddress(string ip)
        {
            if (!IpAdresses.Any(x => x.IpAddress.Equals(ip)))
            {
                IpAdresses.Add(new IpadressModel() { IpAddress = ip, Counter = 1 });
                return;
            }

            var ipaddres = IpAdresses.FirstOrDefault(x => x.IpAddress.Equals(ip));
            if (ipaddres.Counter == BannedRequests)
            {
                Banned.Push(ip);
                IpAdresses.Remove(ipaddres);
            }
            else
            {
                ipaddres.Counter++;
            }
        }

        #region Timers
        /// <summary>
        /// Creates the timer that substract a request
        /// from the _IpAddress dictionary.
        /// </summary>
        private static Timer CreateTimer()
        {
            Timer timer = GetTimer(ReductionInterval);
            timer.Elapsed += new ElapsedEventHandler(TimerElapsed);
            return timer;
        }
        /// <summary>
        /// Creates the timer that removes 1 banned IP address
        /// everytime the timer is elapsed.
        /// </summary>
        /// <returns></returns>
        private static Timer CreateBanningTimer()
        {
            Timer timer = GetTimer(ReleaseInterval);
            timer.Elapsed += delegate
            {
                if (Banned.Count == 0) return;
                Banned?.Pop();
            };
            return timer;
        }
        /// <summary>
        /// Creates a simple timer instance and starts it.
        /// </summary>
        /// <param name="interval">The interval in milliseconds.</param>
        private static Timer GetTimer(int interval)
        {
            Timer timer = new Timer();
            timer.Interval = interval;
            timer.Start();

            return timer;
        }
        /// <summary>
        /// Substracts a request from each IP address in the collection.
        /// </summary>
        private static void TimerElapsed(object sender, ElapsedEventArgs e)
        {
            for (int i = 0; i < IpAdresses.Count; i++)
            {
                IpAdresses[i].Counter--;
                if (IpAdresses[i].Counter == 0)
                    IpAdresses.Remove(IpAdresses[i]);
            }
        }
        #endregion
    }
    public static class DosAttackMiddlewareExtensions
    {
        public static IApplicationBuilder UseDosAttackMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<DosAttackMiddleware>();
        }
    }
}


```

