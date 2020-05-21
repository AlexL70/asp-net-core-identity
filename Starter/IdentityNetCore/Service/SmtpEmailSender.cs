using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace IdentityNetCore.Service
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IOptions<SmtpOptions> _options;

        public SmtpEmailSender(IOptions<SmtpOptions> options)
        {
            _options = options;
        }

        public async Task SendEmailAsync(string toAddress, string subject, string message)
        {
            var mailMessage = new MailMessage(_options.Value.FromAddress, toAddress, subject, message);
            using(var client = new SmtpClient(_options.Value.Host, _options.Value.Port)
            {
                Credentials = new NetworkCredential(_options.Value.Username, _options.Value.Password)
            })
            {
                await client.SendMailAsync(mailMessage);
            }
        }
    }
}
