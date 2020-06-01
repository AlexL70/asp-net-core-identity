using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityNetCore.Helpers;
using IdentityNetCore.Models;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Internal;

namespace IdentityNetCore.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailSender _emailSender;

        public IdentityController(UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailSender = emailSender;
        }

        public IActionResult SignUp()
        {
            var model = new SignUpViewModel() { Role = "Member" };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignUpViewModel model)
        {
            if (ModelState.IsValid)
            {
                //  Role creating code is just for learning purposes
                //  Never do it in a real life
                if (!await _roleManager.RoleExistsAsync(model.Role))
                {
                    var result = await _roleManager.CreateAsync(new IdentityRole {Name = model.Role});
                    if (!result.Succeeded)
                    {
                        ModelState.AddModelError("Role", $"Role {model.Role} cannot be created");
                        return View(model);
                    }
                }

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
                        //user = await _userManager.FindByEmailAsync(model.Email);
                        //var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        //var confirmationLink = Url.ActionLink(nameof(ConfirmEmail),
                        //    nameof(IdentityController).CutOffController(), new {userId = user.Id, @token = token});
                        //await _emailSender.SendEmailAsync(model.Email, "Please confirm your email address",
                        //    $"Please click to the link: {confirmationLink}");


                        var addToRoleResult = await _userManager.AddToRoleAsync(user, model.Role);
                        if (!addToRoleResult.Succeeded)
                        {
                            ModelState.AddModelError($"Role", $"Cannot assign role {model.Role} to user {model.Email}");
                            return View(model);
                        }

                        var claim = new Claim("Department", model.Department);
                        var addClaimResult = await _userManager.AddClaimAsync(user, claim);

                        if (!addClaimResult.Succeeded)
                        {
                            ModelState.AddModelError("Claim", $"Cannot add department {model.Department}");
                        }

                        return RedirectToAction(nameof(SignIn));
                    }

                    ModelState.AddModelError(nameof(SignUp), result.Errors.Select(e => e.Description).Join("<br>"));
                }

                ModelState.AddModelError(nameof(SignUp), "User with this email already exists.");
            }

            return View(model);
        }

        [Authorize]
        public async Task<IActionResult> MfaSetup()
        {
            const string Provider = "Asp.Net_Identity";

            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var model = new MfaViewModel
            {
                Token = token,
                QrCodeUrl = $"otpauth://totp/{Provider}:{user.Email}?secret={token}&issuer={Provider}&digits=6"
            };


            return View(model);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> MfaSetup(MfaViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user,
                    _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (succeeded)
                {
                    var result = _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Sorry, your MFA code cannot be validated.");
                }
            }

            return View(model);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user != null && !user.EmailConfirmed)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    RedirectToAction(nameof(SignIn));
                }

                return BadRequest(result.Errors.Select(e => e.Description).Join(". "));
            }

            if (user == null)
            {
                return new NotFoundResult();
            }

            if (user.EmailConfirmed)
            {
                RedirectToAction(nameof(SignIn));
            }

            return new BadRequestResult();
        }

        public IActionResult SignIn()
        {
            return View(new SignInViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> SignIn(SignInViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, false);

            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(MFACheck));
            }

            if (!result.Succeeded)
            {
                ModelState.AddModelError("Login", "Sign in is not successful.");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Username);
            if (await _userManager.IsInRoleAsync(user, "Admin"))
            {
                return RedirectToAction(nameof(HomeController.Admin), nameof(HomeController).CutOffController());
            }

            if (await _userManager.IsInRoleAsync(user, "Member"))
            {
                return RedirectToAction(nameof(HomeController.Member), nameof(HomeController).CutOffController());
            }

            return RedirectToAction(nameof(HomeController.Index), nameof(HomeController).CutOffController());
        }

        public IActionResult MFACheck()
        {
            return View(new MFACheckViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> MFACheck(MFACheckViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, false, false);

                if (result.Succeeded)
                {
                    return RedirectToAction(nameof(HomeController.Index), nameof(HomeController).CutOffController());
                }
            }

            return View(model);
        }

        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            var props = _signInManager.ConfigureExternalAuthenticationProperties(provider, returnUrl);
            var callBackUrl = Url.Action(nameof(ExternalLoginCallback));
            props.RedirectUri = callBackUrl;
            return Challenge(props, provider);
        }

        public async Task<IActionResult> ExternalLoginCallback()
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            var emailClaim = info.Principal.Claims.Single(_ => _.Type == ClaimTypes.Email);
            var user = await _userManager.FindByEmailAsync(emailClaim.Value);
            if (user == null)
            {
                user = new IdentityUser { 
                    Email = emailClaim.Value, 
                    UserName = emailClaim.Value
                };
                await _userManager.CreateAsync(user);
                await _userManager.AddLoginAsync(user, info);
            }
            await _signInManager.SignInAsync(user, false);
            return RedirectToAction(nameof(HomeController.Index), nameof(HomeController).CutOffController());
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        public async Task<IActionResult> SignOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(SignIn));
        }
    }
}
