using System.ComponentModel.DataAnnotations;

namespace IdentityNetCore.Models
{
    public class MfaViewModel
    {
        [Required]
        public string Token { get; set; }

        [Required]
        public string Code { get; set; }

        [Required]
        public string QrCodeUrl { get; set; }
    }
}
