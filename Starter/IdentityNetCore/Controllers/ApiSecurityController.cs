using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityNetCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace IdentityNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApiSecurityController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public ApiSecurityController(IConfiguration configuration,
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager)
        {
            _configuration = configuration;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [AllowAnonymous]
        [Route(template: "Auth")]
        [HttpPost]
        public async Task<IActionResult> TokenAuth(SignInViewModel model)
        {
            const string section = "ApiSecurity";
            var issuer = _configuration[$"{section}:TokenIssuer"];
            var audience = _configuration[$"{section}:TokenAudience"];
            var keyBytes = Encoding.UTF8.GetBytes( _configuration[$"{section}:TokenKey"]);

            if (ModelState.IsValid)
            {
                var signInResult =
                    await _signInManager.PasswordSignInAsync(model.Username, model.Password, false, true);

                if (signInResult.Succeeded)
                {
                    var user = _userManager.FindByEmailAsync(model.Username);
                    if (user != null)
                    {
                        var claims = new[]
                        {
                            new Claim(JwtRegisteredClaimNames.Email, model.Username), 
                            new Claim(JwtRegisteredClaimNames.Jti, user.Id.ToString()), 
                        };

                        var theKey = new SymmetricSecurityKey(keyBytes);
                        var creds = new SigningCredentials(theKey, SecurityAlgorithms.HmacSha256);
                        var token = new JwtSecurityToken(issuer, audience, claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: creds);

                        return Ok(new {token = new JwtSecurityTokenHandler().WriteToken(token)});
                    }
                }

                ModelState.AddModelError("SignIn", "Failed");
            }

            return BadRequest(ModelState);
        }
    }
}
