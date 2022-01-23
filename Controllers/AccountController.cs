using Microsoft.AspNetCore.Mvc;
using JWTWebApiPractice.Model;
using System.Security.Cryptography;
using System.Security.Claims;

namespace JWTWebApiPractice.Controllers
{
    [ApiController]
    [Route("Api/[Controller]")]
    public class AccountController:ControllerBase
    {

        private static User user=new User();
        private readonly IConfiguration configuration;

        public AccountController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpPost("RegisterDetails")]
        public async Task<ActionResult<User>> RegisterDetails(UserDto request)
        {

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt=passwordSalt;

            return Ok(user);


        }

        [HttpPost("LoginDetails")]
        public async Task<ActionResult> LoginDetails(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return BadRequest("Username not valid");
            }
            if (!verifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt)) 
            {
                return BadRequest("Password not valid");
            }


            string Token = CreateToken(user);

            return Ok(Token);

        }


        private void CreatePasswordHash(string password,out byte[] passwordHash,out byte[] passwordSalt)
        {
            using(var hmac=new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash= hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }


        }


        private bool verifyPasswordHash(string password,byte[] passwordHash,byte[] passwordSalt)
        {
            using(var hmac=new HMACSHA512(passwordSalt))
            {
                var Computehash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return Computehash.SequenceEqual(passwordHash);

            }
        }



        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
               new Claim(ClaimTypes.Name,user.Username)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(configuration.GetSection("Appsetting:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var Token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
                );

            return Token.ToString();

            
        

        }

    }
}
