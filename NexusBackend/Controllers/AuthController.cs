using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NexusBackend.DTOs;
using NexusBackend.Helpers;
using NexusBackend.Services;

namespace NexusBackend.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDTO dto)
    {
        var result = await _authService.RegisterAsync(dto);
        return StatusCode(201, ApiResponse<AuthResponseDTO>.Created(result, "Registered successfully."));
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDTO dto)
    {
        var result = await _authService.LoginAsync(dto);
        return Ok(ApiResponse<AuthResponseDTO>.Ok(result, "Logged in successfully."));
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenDTO dto)
    {
        var result = await _authService.RefreshTokenAsync(dto.RefreshToken);
        return Ok(ApiResponse<AuthResponseDTO>.Ok(result, "Token refreshed successfully."));
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] RefreshTokenDTO dto)
    {
        await _authService.LogoutAsync(dto.RefreshToken);
        return Ok(ApiResponse<string>.Ok("Logged out successfully."));
    }

    [HttpGet("google/login")]
    public IActionResult GoogleLogin()
    {
        var redirectUrl = Url.Action("GoogleCallback", "Auth");
        var properties = new AuthenticationProperties
        {
            RedirectUri = redirectUrl
        };
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback()
    {
        var result = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);
        if (!result.Succeeded)
            return Redirect("https://nexus-frontend.t9am-w0rk.workers.dev/login?error=google_failed");

        var email = result.Principal!.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
        var name = result.Principal.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;

        if (email == null)
            return Redirect("https://nexus-frontend.t9am-w0rk.workers.dev/login?error=no_email");

        var user = await _authService.FindOrCreateGoogleUserAsync(email, name ?? email);
        var tokens = await _authService.GenerateTokensForUserAsync(user);

        return Redirect($"https://nexus-frontend.t9am-w0rk.workers.dev/auth/callback?accessToken={tokens.AccessToken}&refreshToken={tokens.RefreshToken}");
    }
}