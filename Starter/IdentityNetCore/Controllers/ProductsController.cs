using System.Collections.Generic;
using IdentityNetCore.Models;
using Microsoft.AspNetCore.Mvc;

namespace IdentityNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
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
