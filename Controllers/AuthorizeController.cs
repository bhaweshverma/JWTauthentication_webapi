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

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]/[action]")]
    public class AuthorizeController : Controller
    {
        private IConfiguration _config;
        private readonly UserManager<User> _userManager; 
        private readonly SignInManager<User> _signInManager;
        private readonly ILogger _logger;

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
            var message = $"Register action got hit at {DateTime.UtcNow.ToLongTimeString()}";
            _logger.LogInformation(message);

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
                        //await _signInManager.SignInAsync(user, isPersistent:false);
                        return Ok(new {message = "User successfully registered!"});
                    }

                    foreach(var error in result.Errors)
                    {
                        errors = error + " *** "+ error.Description;
                    }

                    response = BadRequest(new {error = errors});
                }
                else
                {
                    response = BadRequest();
                }
            }
            
            return response;
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Token([FromBody] User loggedUser, [FromHeader] string JWTAppKey, [FromHeader] string JWTAppSecret)
        {
            var message = $"Token action got hit at {DateTime.UtcNow.ToLongTimeString()}";
            _logger.LogInformation(message);

            IActionResult response = Unauthorized();
            
            if(ModelState.IsValid)
            {
                if((JWTAppKey == _config["JWTApp:Key"]) && (JWTAppSecret == _config["JWTApp:Secret"]))
                {
                    Task<bool> isUserAuthenticated = AuthenticateUser(loggedUser.Email, loggedUser.Password);
                    if(isUserAuthenticated.Result == true)
                    {
                        var tokenString = GenerateJsonWebToken(loggedUser);
                        response = Ok(new { token = tokenString, expires_in = 3600 } );
                    }
                }
                else
                {
                    return BadRequest();
                }
            }

            return response;
        }

        [HttpGet]
        public bool ValidateToken([FromHeader] string token)
        {
            var message = $"ValidateToken action got hit at {DateTime.UtcNow.ToLongTimeString()}";
            _logger.LogInformation(message);

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
            catch
            {
                return false;
            }
            return true;
        }
        private string GenerateJsonWebToken(User user)
        {
             var message = $"Attempt to GenerateJsonWebToken (action) got hit at {DateTime.UtcNow.ToLongTimeString()} for user {user.Email}";
            _logger.LogInformation(message);

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
            var message = $"Attempt to AuthenticateUser (action) got hit at {DateTime.UtcNow.ToLongTimeString()} for user {userEmail}";
            _logger.LogInformation(message);

            //first find user by checking if email id is valid or not
            var resultUser = await _userManager.FindByEmailAsync(userEmail);
            if(resultUser == null)
            {
                return false;
            }

            var validateCredentials = await _userManager.CheckPasswordAsync(resultUser, userPassword);
            
            return validateCredentials;
        }
    
    }
}