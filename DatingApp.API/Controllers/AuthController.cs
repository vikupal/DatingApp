
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;

        public object SecurityAlogorithms { get; private set; }

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            this._config = config;
            this._repo = repo;
        }

        [HttpPost("register")]

        public async Task<IActionResult> Register(UserForRegisterDto uesrForRegisterDto)
        {                   
            uesrForRegisterDto.UserName = uesrForRegisterDto.UserName.ToLower();
            if(await _repo.UserExists(uesrForRegisterDto.UserName)){
                    return BadRequest("UserName already exists");
            }

            var userToCreate = new User
            {
                UserName = uesrForRegisterDto.UserName
            };

            var createduser = await _repo.Register(userToCreate, uesrForRegisterDto.Password);

            return StatusCode(201);
        }

        [HttpPost("login")]        
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var userFromRepo = await _repo.Login(userForLoginDto.UserName.ToLower(), userForLoginDto.Password);

            if(userFromRepo == null)
                return Unauthorized();
            
            var claims = new []
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.UserName)
            };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value)); 

                var creads  = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

                var tokenDescriptior = new SecurityTokenDescriptor {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.Now.AddDays(1),
                    SigningCredentials = creads

                };

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDescriptior);

                return Ok(new {
                    token = tokenHandler.WriteToken(token)
                });            
        }
    }
}