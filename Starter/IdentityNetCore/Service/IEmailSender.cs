using System.Threading.Tasks;

namespace IdentityNetCore.Service
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string toAddress, string subject, string message);
    }
}
