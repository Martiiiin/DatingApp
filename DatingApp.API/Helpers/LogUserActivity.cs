using System;
using System.Security.Claims;
using System.Threading.Tasks;
using DatingApp.API.Data;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;

namespace DatingApp.API.Helpers
{
    public class LogUserActivity : IAsyncActionFilter
    {
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var resultContext = await next();

            // Obtain userId from the token's claims in user response
            var userId = int.Parse(resultContext.HttpContext.User
                .FindFirst(ClaimTypes.NameIdentifier).Value);

            // Obtain repo's active instance as a service
            var repo = resultContext.HttpContext.RequestServices.GetService<IDatingRepository>();
            var user = await repo.GetUser(userId);
            user.LastActive = DateTime.Now;

            await repo.SaveAll();
        }
    }
}