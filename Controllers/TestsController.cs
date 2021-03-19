using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace API.Controllers
{
    [Route("api/v1/[controller]")]
    public class TestsController : ControllerBase
    {
        private readonly IJwtHandler _jwtHandler;
        public TestsController(IJwtHandler jwtHandler)
        {
            _jwtHandler = jwtHandler;
        }

        [HttpPost]
        [Route("token")]
        public IActionResult GenerateJwtAsync()
        {

            var claims = new JwtCustomClaims
            {
                FirstName = "Nk",
                LastName = "Nk",
                Email = "123@@mail.com"
            };

            var jwt = _jwtHandler.CreateToken(claims);

            return Ok(jwt);
        }

        [HttpPost]
        [Route("token/validate")]
        public IActionResult ValidateJwtAsync([FromBody] string token)
        {

            if (_jwtHandler.ValidateToken(token))
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(token) as JwtSecurityToken;

                var claims = new JwtCustomClaims
                {
                    FirstName = jwtToken.Claims.First(claim => claim.Type == "FirstName").Value,
                    LastName = jwtToken.Claims.First(claim => claim.Type == "LastName").Value,
                    Email = jwtToken.Claims.First(claim => claim.Type == "Email").Value
                };

                return Ok(claims);
            }

            return BadRequest("Token is invalid.");
        }
    }
}
