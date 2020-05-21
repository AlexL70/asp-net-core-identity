using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models
{
    public class SignUpViewModel
    {
        [Required]
        [DataType(DataType.EmailAddress, ErrorMessage = "Email is incorrect.")]
        public string Email { get; set; }
        
        [Required]
        [DataType(DataType.Password, ErrorMessage = "Password is incorrect")]
        public string Password { get; set; }

        [Required]
        public string Role { get; set; }
    }
}
