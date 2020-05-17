using Microsoft.AspNetCore.Identity;

namespace JWTAuthentication.Models
{
    public class User : IdentityUser
    {
        public override string UserName { get; set; }
        
        public override string Email { get; set; }
        
        public string Password { get; set;}

        public string UserType { get; set; } 

        public string Scope { get; set; }

        public int Age { get; set; }
    }
}