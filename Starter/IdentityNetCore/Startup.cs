using System;
using IdentityNetCore.Controllers;
using IdentityNetCore.Data;
using IdentityNetCore.Helpers;
using IdentityNetCore.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace IdentityNetCore
{
    public class Startup
    {
        public Startup(
            //  IConfiguration configuration,
            IWebHostEnvironment env)
        {
            Configuration = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", true, true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", true)
                .AddEnvironmentVariables()
                .Build();
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var connectionString = Configuration["ConnectionStrings:Default"];
            services.AddDbContext<ApplicationDbContext>(_ => _.UseSqlServer(connectionString));

            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.Password.RequiredLength = 3;
                options.Password.RequireDigit = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;

                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);

                //options.SignIn.RequireConfirmedEmail = true;
            });

            services.ConfigureApplicationCookie(option =>
            {
                option.LoginPath = $"/{nameof(IdentityController).CutOffController()}/{nameof(IdentityController.SignIn)}";
                option.AccessDeniedPath =
                    $"/{nameof(IdentityController).CutOffController()}/{nameof(IdentityController.AccessDenied)}";
                option.ExpireTimeSpan = TimeSpan.FromHours(1);
                option.SlidingExpiration = true;
            });

            services.Configure<SmtpOptions>(Configuration.GetSection("Smtp"));
            services.AddSingleton<IEmailSender, SmtpEmailSender>();
            services.AddAuthorization(option =>
            {
                option.AddPolicy("AdminDep", p =>
                {
                    p.RequireClaim("Department", "Administrative").RequireRole("Admin");
                });
            });
            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();


            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
