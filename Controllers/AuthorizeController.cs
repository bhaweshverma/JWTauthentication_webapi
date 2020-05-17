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

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]/[action]")]
    public class AuthorizeController : Controller
    {
        private IConfiguration _config;
        private readonly UserManager<User> _userManager; 
        private readonly SignInManager<User> _signInManager;

        public AuthorizeController(IConfiguration config, 
            UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _config = config;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] User newUser, [FromHeader] string JWTAppKey, [FromHeader] string JWTAppSecret)
        {
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