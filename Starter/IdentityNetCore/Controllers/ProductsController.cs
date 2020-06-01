using System.Collections.Generic;
using IdentityNetCore.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class ProductsController : ControllerBase
    {
        [Route(template: "List")]
        public List<Product> GetList()
        {
            return new List<Product>
            {
                new Product { Name = "Chair", Price = 97.12m },
                new Product { Name = "Desk", Price = 120.50m }
            };
        }
    }
}
