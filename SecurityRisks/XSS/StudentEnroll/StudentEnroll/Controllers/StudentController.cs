using Microsoft.AspNetCore.Mvc;
using StudentEnroll.Models;

namespace StudentEnroll.Controllers
{
    public class StudentsController : Controller
    {
        public IActionResult Index()
        {
            return View("Index");
        }


        [HttpPost]
        public IActionResult SignUp(StudentViewModel model)
        {
            return View("Result", model);
        }
    }
}
