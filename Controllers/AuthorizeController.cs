using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuthentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System.Linq;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]/[action]")]
    public class AuthorizeController : Controller
    {
        private IConfiguration _config;
        private readonly UserManager<User> _userManager; 
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger<AuthorizeController> _logger;
        
        public AuthorizeController(IConfiguration config, 
            UserManager<User> userManager, SignInManager<User> signInManager, 
            ILogger<AuthorizeController> logger)
        {
            _config = config;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] User newUser, [FromHeader] string JWTAppKey, [FromHeader] string JWTAppSecret)
        {
            var agent = Request.Headers[HeaderNames.UserAgent].ToString();
            var message = $"Request to Register new user - {newUser.Email} from {agent} at {DateTime.UtcNow.ToLongTimeString()} ";
           
            string errors = string.Empty;
            IActionResult response = null;
            var x = _config["JWTApp:Key"];
            var y =  _config["JWTApp:Secret"];

            if(ModelState.IsValid)
            {
                if((JWTAppKey == _config["JWTApp:Key"]) && (JWTAppSecret == _config["JWTApp:Secret"]))
                {
                    var user = new User{
                        UserName = newUser.UserName,
                        Email = newUser.Email
                    };
                    var result = await _userManager.CreateAsync(user, newUser.Password);

                    if(result.Succeeded)
                    {
                        _logger.LogInformation(message + "SUCCESSFULLY executed!");
                        return Ok(new {message = "User successfully registered!", email = newUser.Email});
                    }

                    foreach(var error in result.Errors)
                    {
                        errors += error.Description + " | ";
                    }
                     _logger.LogError(message + "FAILED with exception - "+ errors);    
                    response = BadRequest(new {error = errors});
                }
                else
                {
                     _logger.LogError(message + "FAILED with exception - "+ "API KEY or SECRET MISMATCH");
                    response = BadRequest();
                }
            }
            else
            {
                errors = string.Join(" | ", ModelState.Values
                                        .SelectMany(v => v.Errors)
                                        .Select(e => e.ErrorMessage));

                _logger.LogError(message + "FAILED with exception - "+ errors);
            }
            return response;
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Token([FromBody] User loggedUser, [FromHeader] string JWTAppKey, [FromHeader] string JWTAppSecret)
        {
            var agent = Request.Headers[HeaderNames.UserAgent].ToString();
            var message = $"Request for new Token for user - {loggedUser.Email} from {agent} at {DateTime.UtcNow.ToLongTimeString()} ";
            
            IActionResult response = Unauthorized();
            
            if(ModelState.IsValid)
            {
                if((JWTAppKey == _config["JWTApp:Key"]) && (JWTAppSecret == _config["JWTApp:Secret"]))
                {
                    Task<bool> isUserAuthenticated = AuthenticateUser(loggedUser.Email, loggedUser.Password);
                    if(isUserAuthenticated.Result == true)
                    {
                        var tokenString = GenerateJsonWebToken(loggedUser);
                        if(!string.IsNullOrEmpty(tokenString))
                        {
                            _logger.LogInformation(message + "SUCCESSFULLY executed!");
                            response = Ok(new { token = tokenString, expires_in = 3600 } );
                        }
                        else
                        {
                            _logger.LogError(message + "FAILED with exception - "+ "EMPTY TOKEN GENERATED");
                        }
                    }
                }
                else
                {
                     _logger.LogError(message + "FAILED with exception - "+ "INCORRECT KEY SECRET INFO");
                    return BadRequest();
                }
            }
            else
            {   
                var errors = string.Join(" | ", ModelState.Values
                                        .SelectMany(v => v.Errors)
                                        .Select(e => e.ErrorMessage));
             
                _logger.LogError(message + "FAILED with exception - "+ errors);
                return response;
            }
            
            return response;
        }

        [HttpGet]
        public bool ValidateToken([FromHeader] string token)
        {
            var agent = Request.Headers[HeaderNames.UserAgent].ToString();
            var message = $"Request to ValidateToken from {agent} at {DateTime.UtcNow.ToLongTimeString()} ";
           
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters{
                        
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = _config["JWT:Issuer"],
                        ValidAudience = _config["JWT:Issuer"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"]))

                }, out SecurityToken validatedToken);
            }
            catch(Exception e)
            {
                _logger.LogError(message + "FAILED with exception - "+ e.Message);
                return false;
            }
            _logger.LogInformation(message + "SUCCESSFULLY executed!");
            return true;
        }
        private string GenerateJsonWebToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"]));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new [] {
                //new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                _config["JWT:Issuer"],
                _config["JWT:Issuer"],
                claims,
                null,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials
            );
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private async Task<bool> AuthenticateUser(string userEmail, string userPassword)
        {
            var message = $"Attempt to Authenticate user - {userEmail} at {DateTime.UtcNow.ToLongTimeString()} ";
            
            //first find user by checking if email id is valid or not
            var resultUser = await _userManager.FindByEmailAsync(userEmail);
            if(resultUser == null)
            {
                _logger.LogError(message + "FAILED with exception - "+ "NO USER FOUND.");
                return false;
            }

            var validateCredentials = await _userManager.CheckPasswordAsync(resultUser, userPassword);
            
            if(validateCredentials)
            _logger.LogInformation(message + "SUCCESSFULLY executed!");
            else
            _logger.LogError(message + "FAILED with exception - "+ "Invalid Password.");
                
            return validateCredentials;
        }
    
    }
}