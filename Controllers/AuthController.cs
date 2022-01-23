using Microsoft.AspNetCore.Mvc;
using JWTWebApiPractice.Model;
using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
// using System.IdentityModel.Tokens.Jwt;  it is globally declared
// using Microsoft.IdentityModel.Tokens;  it is globally declared in program.cs file 

namespace JWTWebApiPractice.Controllers
{

    [Route("api/[Controller]")]
    [ApiController]
    public class AuthController :ControllerBase
    { 
        private static User user=new User();
        private readonly IConfiguration configuration;

        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }


        [HttpPost("Register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePassowrdHash(request.Password,out byte[] Hash,out byte[] salt);

            user.PasswordHash = Hash;
            user.PasswordSalt = salt;
            user.Username= request.Username;

            return Ok (user);
        }


        [HttpPost("Login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.Username!=request.Username)
            {
                return BadRequest("Username is not found");
            }

            if (!VerifyPassword(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("password is not valid");
            }

            string Token = CreateToken(user);

            return Ok(Token);
        }


        private void CreatePassowrdHash(string password, out byte[] passwordHash,out byte[] passwordSalt)
        {
            using(var hmac=new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }

        }


        private bool VerifyPassword(string password,byte[] passwordHash,byte[] passwordSalt)
        {

            using(var hmac=new HMACSHA512(passwordSalt))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

                return computeHash.SequenceEqual(passwordHash);
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

            var JWT=new JwtSecurityTokenHandler().WriteToken(Token);

            return JWT;   
        }




    }
}
