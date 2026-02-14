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
            
            // reCAPTCHA v3: Check both success and score
            bool success = json.Value<bool>("success");
            double score = json.Value<double?>("score") ?? 0.0;
            
            // Score ranges from 0.0 to 1.0
            // 1.0 is very likely a legitimate interaction, 0.0 is very likely a bot
            // Use configured threshold to determine if user should be allowed
            double threshold = _reCaptchaSettings.ScoreThreshold;
            
            return success && score >= threshold;
        }
    }

    public class ReCaptchaSettings
    {
        public string SiteKey { get; set; }
        public string SecretKey { get; set; }
        public double ScoreThreshold { get; set; } = 0.5; // Default threshold: 0.5 (50%)
    }
}
