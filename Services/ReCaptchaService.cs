using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace BookwormsOnline.Services
{
    public class ReCaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly ReCaptchaSettings _reCaptchaSettings;

        public ReCaptchaService(HttpClient httpClient, IOptions<ReCaptchaSettings> reCaptchaSettings)
        {
            _httpClient = httpClient;
            _reCaptchaSettings = reCaptchaSettings.Value;
        }

        public async Task<bool> Verify(string token)
        {
            var response = await _httpClient.PostAsync($"https://www.google.com/recaptcha/api/siteverify?secret={_reCaptchaSettings.SecretKey}&response={token}", null);
            var jsonString = await response.Content.ReadAsStringAsync();
            var json = JObject.Parse(jsonString);
            return json.Value<bool>("success");
        }
    }

    public class ReCaptchaSettings
    {
        public string SiteKey { get; set; }
        public string SecretKey { get; set; }
    }
}
