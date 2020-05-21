using System.Linq;
using System.Threading.Tasks;
using IdentityNetCore.Helpers;
using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Internal;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _emailSender;

        public IdentityController(UserManager<IdentityUser> userManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _emailSender = emailSender;
        }

        public async Task<IActionResult> SignUp()
        {
            var model = new SignUpViewModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignUpViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (await _userManager.FindByEmailAsync(model.Email) == null)
                {
                    var user = new IdentityUser
                    {
                        Email = model.Email,
                        UserName = model.Email
                    };
                    var result = await _userManager.CreateAsync( user, model.Password);

                    if (result.Succeeded)
                    {
                        user = await _userManager.FindByEmailAsync(model.Email);
                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var confirmationLink = Url.ActionLink(nameof(ConfirmEmail),
                            nameof(IdentityConstants).CutOffController(), new {userId = user.Id, token = token});
                        await _emailSender.SendEmailAsync(model.Email, "Please confirm your email address",
                            $"Please click to the link: {confirmationLink}");
                        return RedirectToAction(nameof(SignIn));
                    }

                    ModelState.AddModelError(nameof(SignUp), result.Errors.Select(e => e.Description).Join("<br>"));
                }

                ModelState.AddModelError(nameof(SignUp), "User with this email already exists.");
            }

            return View(model);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            return new OkResult();
        }

        public async Task<IActionResult> SignIn()
        {
            return View();
        }

        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }
    }
}
