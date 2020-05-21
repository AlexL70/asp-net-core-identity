﻿using System.Linq;
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

        public async Task<IActionResult> SignUp()
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

        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }
    }
}
